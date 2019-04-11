package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/go-acme/lego/providers/dns/cloudflare"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/lego"

	"github.com/ericchiang/k8s"
	corev1 "github.com/ericchiang/k8s/apis/core/v1"
	eventsv1beta1 "github.com/ericchiang/k8s/apis/events/v1beta1"
	metav1 "github.com/ericchiang/k8s/apis/meta/v1"
)

const annotationLetsEncryptCertificate string = "estafette.io/letsencrypt-certificate"
const annotationLetsEncryptCertificateHostnames string = "estafette.io/letsencrypt-certificate-hostnames"

const annotationLetsEncryptCertificateState string = "estafette.io/letsencrypt-certificate-state"

// LetsEncryptCertificateState represents the state of the secret with respect to Let's Encrypt certificates
type LetsEncryptCertificateState struct {
	Enabled     string `json:"enabled"`
	Hostnames   string `json:"hostnames"`
	LastRenewed string `json:"lastRenewed"`
	LastAttempt string `json:"lastAttempt"`
}

var (
	version   string
	branch    string
	revision  string
	buildDate string
	goVersion = runtime.Version()
)

var (
	addr = flag.String("listen-address", ":9101", "The address to listen on for HTTP requests.")

	// seed random number
	r = rand.New(rand.NewSource(time.Now().UnixNano()))

	// define prometheus counter
	certificateTotals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "estafette_letsencrypt_certificate_totals",
			Help: "Number of generated certificates with LetsEncrypt.",
		},
		[]string{"namespace", "status", "initiator", "type"},
	)
)

func init() {
	// metrics have to be registered to be exposed
	prometheus.MustRegister(certificateTotals)
}

func main() {

	// parse command line parameters
	flag.Parse()

	// log as severity for stackdriver logging to recognize the level
	zerolog.LevelFieldName = "severity"

	// set some default fields added to all logs
	log.Logger = zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "estafette-letsencrypt-certificate").
		Str("version", version).
		Logger()

	// use zerolog for any logs sent via standard log library
	stdlog.SetFlags(0)
	stdlog.SetOutput(log.Logger)

	// log startup message
	log.Info().
		Str("branch", branch).
		Str("revision", revision).
		Str("buildDate", buildDate).
		Str("goVersion", goVersion).
		Msg("Starting estafette-letsencrypt-certificate...")

	// create cloudflare api client
	cfAPIKey := os.Getenv("CF_API_KEY")
	if cfAPIKey == "" {
		log.Fatal().Msg("CF_API_KEY is required. Please set CF_API_KEY environment variable to your Cloudflare API key.")
	}
	cfAPIEmail := os.Getenv("CF_API_EMAIL")
	if cfAPIEmail == "" {
		log.Fatal().Msg("CF_API_EMAIL is required. Please set CF_API_KEY environment variable to your Cloudflare API email.")
	}

	// create kubernetes api client
	client, err := k8s.NewInClusterClient()
	if err != nil {
		log.Fatal().Err(err)
	}
	log.Info().Msg("Creating Event...")
	event := new(eventsv1beta1.Event)
	err = postEventAboutStatus(client, event, "EventAdded", "The reason", "Warning")
	if err != nil{
		log.Fatal().Err(err)
	}

	// start prometheus
	go func() {
		log.Debug().
			Str("port", *addr).
			Msg("Serving Prometheus metrics...")

		http.Handle("/metrics", promhttp.Handler())

		if err := http.ListenAndServe(*addr, nil); err != nil {
			log.Fatal().Err(err).Msg("Starting Prometheus listener failed")
		}
	}()

	// define channel used to gracefully shutdown the application
	gracefulShutdown := make(chan os.Signal)

	signal.Notify(gracefulShutdown, syscall.SIGTERM, syscall.SIGINT)

	waitGroup := &sync.WaitGroup{}

	// watch secrets for all namespaces
	go func(waitGroup *sync.WaitGroup) {
		// loop indefinitely
		for {
			log.Info().Msg("Watching secrets for all namespaces...")
			var secret corev1.Secret
			watcher, err := client.Watch(context.Background(), k8s.AllNamespaces, &secret, k8s.Timeout(time.Duration(300)*time.Second))
			defer watcher.Close()

			if err != nil {
				log.Error().Err(err)
			} else {
				// loop indefinitely, unless it errors
				for {
					secret := new(corev1.Secret)
					eventType, err := watcher.Next(secret)
					if err != nil {
						log.Error().Err(err)
						break
					}

					if eventType == k8s.EventAdded || eventType == k8s.EventModified {
						waitGroup.Add(1)
						status, err := processSecret(client, secret, fmt.Sprintf("watcher:%v", eventType))
						certificateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": status, "initiator": "watcher", "type": "secret"}).Inc()
						waitGroup.Done()

						if err != nil {
							log.Error().Err(err)
							continue
						}
					}
				}
			}

			// sleep random time between 22 and 37 seconds
			sleepTime := applyJitter(30)
			log.Info().Msgf("Sleeping for %v seconds...", sleepTime)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}(waitGroup)

	go func(waitGroup *sync.WaitGroup) {
		// loop indefinitely
		for {

			// get secrets for all namespaces
			log.Info().Msg("Listing secrets for all namespaces...")
			var secrets corev1.SecretList
			err := client.List(context.Background(), k8s.AllNamespaces, &secrets)
			if err != nil {
				log.Error().Err(err)
			}
			log.Info().Msgf("Cluster has %v secrets", len(secrets.Items))

			// loop all secrets
			for _, secret := range secrets.Items {
				waitGroup.Add(1)
				status, err := processSecret(client, secret, "poller")
				certificateTotals.With(prometheus.Labels{"namespace": *secret.Metadata.Namespace, "status": status, "initiator": "poller", "type": "secret"}).Inc()
				waitGroup.Done()

				if err != nil {
					log.Error().Err(err)
					continue
				}
			}

			// sleep random time around 900 seconds
			sleepTime := applyJitter(900)
			log.Info().Msgf("Sleeping for %v seconds...", sleepTime)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}(waitGroup)

	signalReceived := <-gracefulShutdown
	log.Info().
		Msgf("Received signal %v. Waiting for running tasks to finish...", signalReceived)

	waitGroup.Wait()

	log.Info().Msg("Shutting down...")
}

func applyJitter(input int) (output int) {

	deviation := int(0.25 * float64(input))

	return input - deviation + r.Intn(2*deviation)
}

func getDesiredSecretState(secret *corev1.Secret) (state LetsEncryptCertificateState) {

	var ok bool

	// get annotations or set default value
	state.Enabled, ok = secret.Metadata.Annotations[annotationLetsEncryptCertificate]
	if !ok {
		state.Enabled = "false"
	}
	state.Hostnames, ok = secret.Metadata.Annotations[annotationLetsEncryptCertificateHostnames]
	if !ok {
		state.Hostnames = ""
	}

	return
}

func getCurrentSecretState(secret *corev1.Secret) (state LetsEncryptCertificateState) {

	// get state stored in annotations if present or set to empty struct
	letsEncryptCertificateStateString, ok := secret.Metadata.Annotations[annotationLetsEncryptCertificateState]
	if !ok {
		// couldn't find saved state, setting to default struct
		state = LetsEncryptCertificateState{}
		return
	}

	if err := json.Unmarshal([]byte(letsEncryptCertificateStateString), &state); err != nil {
		// couldn't deserialize, setting to default struct
		state = LetsEncryptCertificateState{}
		return
	}

	// return deserialized state
	return
}

func makeSecretChanges(kubeClient *k8s.Client, secret *corev1.Secret, initiator string, desiredState, currentState LetsEncryptCertificateState) (status string, err error) {

	cfAPIKey := os.Getenv("CF_API_KEY")
	cfAPIEmail := os.Getenv("CF_API_EMAIL")

	status = "failed"

	// parse last renewed time from state
	lastRenewed := time.Time{}
	if currentState.LastRenewed != "" {
		var err error
		lastRenewed, err = time.Parse(time.RFC3339, currentState.LastRenewed)
		if err != nil {
			lastRenewed = time.Time{}
		}
	}

	lastAttempt := time.Time{}
	if currentState.LastAttempt != "" {
		var err error
		lastAttempt, err = time.Parse(time.RFC3339, currentState.LastAttempt)
		if err != nil {
			lastAttempt = time.Time{}
		}
	}

	// check if letsencrypt is enabled for this secret, hostnames are set and either the hostnames have changed or the certificate is older than 60 days and the last attempt was more than 15 minutes ago
	if desiredState.Enabled == "true" && len(desiredState.Hostnames) > 0 && time.Since(lastAttempt).Minutes() > 15 && (desiredState.Hostnames != currentState.Hostnames || time.Since(lastRenewed).Hours() > float64(60*24)) {

		log.Info().Msgf("[%v] Secret %v.%v - Certificates are more than 60 days old or hostnames have changed (%v), renewing them with Let's Encrypt...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, desiredState.Hostnames)

		// 'lock' the secret for 15 minutes by storing the last attempt timestamp to prevent hitting the rate limit if the Let's Encrypt call fails and to prevent the watcher and the fallback polling to operate on the secret at the same time
		currentState.LastAttempt = time.Now().Format(time.RFC3339)

		// serialize state and store it in the annotation
		letsEncryptCertificateStateByteArray, err := json.Marshal(currentState)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}
		secret.Metadata.Annotations[annotationLetsEncryptCertificateState] = string(letsEncryptCertificateStateByteArray)

		// update secret, with last attempt; this will fire an event for the watcher, but this shouldn't lead to any action because storing the last attempt locks the secret for 15 minutes
		err = kubeClient.Update(context.Background(), secret)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// error if any of the host names is longer than 64 bytes
		hostnames := strings.Split(desiredState.Hostnames, ",")
		for _, hostname := range hostnames {
			if !validateHostname(hostname) {
				err = fmt.Errorf("Hostname %v is invalid", hostname)
				log.Error().Err(err)
				return status, err
			}
		}

		// load account.json
		log.Info().Msgf("[%v] Secret %v.%v - Loading account.json...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		fileBytes, err := ioutil.ReadFile("/account/account.json")
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		var letsEncryptUser LetsEncryptUser
		err = json.Unmarshal(fileBytes, &letsEncryptUser)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// load private key
		log.Info().Msgf("[%v] Secret %v.%v - Loading account.key...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		privateKey, err := loadPrivateKey("/account/account.key")
		if err != nil {
			log.Error().Err(err)
			return status, err
		}
		letsEncryptUser.key = privateKey

		log.Info().Msgf("[%v] Secret %v.%v - Creating lego config...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		config := lego.NewConfig(&letsEncryptUser)

		// create letsencrypt lego client
		log.Info().Msgf("[%v] Secret %v.%v - Creating lego client...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		legoClient, err := lego.NewClient(config)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// get dns challenge
		log.Info().Msgf("[%v] Secret %v.%v - Creating cloudflare provider...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		cloudflareConfig := cloudflare.NewDefaultConfig()
		cloudflareConfig.AuthEmail = cfAPIEmail
		cloudflareConfig.AuthKey =  cfAPIKey
		cloudflareConfig.PropagationTimeout = 10*time.Minute

		cloudflareProvider, err := cloudflare.NewDNSProviderConfig(cloudflareConfig)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// clean up acme challenge records in advance
		for _, hostname := range hostnames {
			log.Info().Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
			err = cloudflareProvider.CleanUp(hostname, "", "123d==")
			if err != nil {
				log.Info().Err(err).Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v failed", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
			}
		}

		// set challenge provider
		legoClient.Challenge.SetDNS01Provider(cloudflareProvider)

		// get certificate
		log.Info().Msgf("[%v] Secret %v.%v - Obtaining certificate...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		request := certificate.ObtainRequest{
			Domains: hostnames,
			Bundle:  true,
		}
		certificates, err := legoClient.Certificate.Obtain(request)

		// clean up acme challenge records afterwards
		for _, hostname := range hostnames {
			log.Info().Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
			err = cloudflareProvider.CleanUp(hostname, "", "123d==")
			if err != nil {
				log.Info().Err(err).Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v failed", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
			}
		}

		// if obtaining secret failed exit and retry after more than 15 minutes
		if err != nil {
			log.Error().Err(err).Msgf("Could not obtain certificates for domains %v", hostnames)
			return status, err
		}

		// update the secret
		currentState = desiredState
		currentState.LastRenewed = time.Now().Format(time.RFC3339)

		log.Info().Msgf("[%v] Secret %v.%v - Updating secret because new certificates have been obtained...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		// serialize state and store it in the annotation
		letsEncryptCertificateStateByteArray, err = json.Marshal(currentState)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}
		secret.Metadata.Annotations[annotationLetsEncryptCertificateState] = string(letsEncryptCertificateStateByteArray)

		// store the certificates
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}

		log.Info().Msgf("[%v] Secret %v.%v - Secret has %v data items before writing the certificates...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, len(secret.Data))

		// ssl keys
		secret.Data["ssl.crt"] = certificates.Certificate
		secret.Data["ssl.key"] = certificates.PrivateKey
		secret.Data["ssl.pem"] = bytes.Join([][]byte{certificates.Certificate, certificates.PrivateKey}, []byte{})
		if certificates.IssuerCertificate != nil {
			secret.Data["ssl.issuer.crt"] = certificates.IssuerCertificate
		}

		jsonBytes, err := json.MarshalIndent(certificates, "", "\t")
		if err != nil {
			log.Error().Msgf("[%v] Secret %v.%v - Unable to marshal CertResource for domain %s\n\t%s", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, certificates.Domain, err.Error())
			return status, err
		}
		secret.Data["ssl.json"] = jsonBytes

		// tls keys for ingress object
		secret.Data["tls.crt"] = certificates.Certificate
		secret.Data["tls.key"] = certificates.PrivateKey
		secret.Data["tls.pem"] = bytes.Join([][]byte{certificates.Certificate, certificates.PrivateKey}, []byte{})
		if certificates.IssuerCertificate != nil {
			secret.Data["tls.issuer.crt"] = certificates.IssuerCertificate
		}
		secret.Data["tls.json"] = jsonBytes

		log.Info().Msgf("[%v] Secret %v.%v - Secret has %v data items after writing the certificates...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, len(secret.Data))

		// update secret, because the data and state annotation have changed
		err = kubeClient.Update(context.Background(), secret)

		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		status = "succeeded"

		log.Info().Msgf("[%v] Secret %v.%v - Certificates have been stored in secret successfully...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)

		return status, nil
	}

	status = "skipped"

	return status, nil
}

func postEventAboutStatus(kubeClient *k8s.Client, event *eventsv1beta1.Event, action string, reason string, note string )(err error){

	now := time.Now()
	secs := int64(now.Unix())
	// event.Metadata = new(metav1.ObjectMeta)
	// event.Metadata.Name = secret.Metadata.Name
	// event.Metadata.Namespace = secret.Metadata.Namespace

	// event.Metadata.CreationTimestamp = new(metav1.Time)
	// event.Metadata.CreationTimestamp.Seconds = &secs

	// event.Metadata.Labels = secret.Metadata.Labels
	log.Info().Msgf(" Starting Function")

	event.EventTime = new(metav1.MicroTime)
	event.EventTime.Seconds = &secs

	event.Action = &action
	event.Note = &note

	err = kubeClient.Create(context.TODO(), event)
	if err != nil {
		log.Error().Err(err)
		return err
	}
	log.Info().Msgf(" Ending Function")

	return
}

func processSecret(kubeClient *k8s.Client, secret *corev1.Secret, initiator string) (status string, err error) {

	status = "failed"

	if &secret != nil && &secret.Metadata != nil && &secret.Metadata.Annotations != nil {

		desiredState := getDesiredSecretState(secret)
		currentState := getCurrentSecretState(secret)
		// event := new(eventsv1beta1.Event)

		status, err = makeSecretChanges(kubeClient, secret, initiator, desiredState, currentState)
		//err = postEventAboutStatus(kubeClient, event, status, "The reason", "Warning")
		return
	}

	status = "skipped"
	return status, nil
}

func validateHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}

	dnsNameParts := strings.Split(hostname, ".")
	// we need at least a subdomain within a zone
	if len(dnsNameParts) < 2 {
		return false
	}

	// each label needs to be max 63 characters and only have alphanumeric or hyphen; or a wildcard star for it's first label
	for index, label := range dnsNameParts {
		if index != 0 || label != "*" {
			matchesInvalidChars, _ := regexp.MatchString("[^a-zA-Z0-9-]", label)
			if matchesInvalidChars {
				return false
			}
		}

		if len(label) > 63 {
			return false
		}
	}
	return true
}
