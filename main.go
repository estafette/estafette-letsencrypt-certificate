package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/cloudflare"

	"github.com/ericchiang/k8s"
	apiv1 "github.com/ericchiang/k8s/api/v1"
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
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "estafette-letsencrypt-certificate").
		Str("version", version).
		Logger()

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
			watcher, err := client.CoreV1().WatchSecrets(context.Background(), k8s.AllNamespaces)
			if err != nil {
				log.Error().Err(err)
			} else {
				// loop indefinitely, unless it errors
				for {
					event, secret, err := watcher.Next()
					if err != nil {
						log.Error().Err(err)
						break
					}

					if *event.Type == k8s.EventAdded || *event.Type == k8s.EventModified {
						waitGroup.Add(1)
						status, err := processSecret(client, secret, fmt.Sprintf("watcher:%v", *event.Type))
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
			secrets, err := client.CoreV1().ListSecrets(context.Background(), k8s.AllNamespaces)
			if err != nil {
				log.Error().Err(err)
			}
			log.Info().Msgf("Cluster has %v secrets", len(secrets.Items))

			// loop all secrets
			if secrets != nil && secrets.Items != nil {
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
			}

			// sleep random time around 900 seconds
			sleepTime := applyJitter(900)
			log.Info().Msgf("Sleeping for %v seconds...", sleepTime)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}(waitGroup)

	signalReceived := <-gracefulShutdown
	log.Info().
		Msgf("Received signal %v. Waiting on running tasks to finish...", signalReceived)

	waitGroup.Wait()

	log.Info().Msg("Shutting down...")
}

func applyJitter(input int) (output int) {

	deviation := int(0.25 * float64(input))

	return input - deviation + r.Intn(2*deviation)
}

func getDesiredSecretState(secret *apiv1.Secret) (state LetsEncryptCertificateState) {

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

func getCurrentSecretState(secret *apiv1.Secret) (state LetsEncryptCertificateState) {

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

func makeSecretChanges(kubeClient *k8s.Client, secret *apiv1.Secret, initiator string, desiredState, currentState LetsEncryptCertificateState) (status string, err error) {

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
		secret, err = kubeClient.CoreV1().UpdateSecret(context.Background(), secret)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// error if any of the host names is longer than 64 bytes
		hostnames := strings.Split(desiredState.Hostnames, ",")
		for _, hostname := range hostnames {
			byteCount := len([]byte(hostname))
			if byteCount > 64 {
				err = fmt.Errorf("Hostname %v is %v bytes long; the maximum length for CN is 64 bytes", hostname, byteCount)
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

		// set dns timeout
		log.Info().Msgf("[%v] Secret %v.%v - Setting acme dns timeout to 600 seconds...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		acme.DNSTimeout = time.Duration(600) * time.Second

		// create letsencrypt acme client
		log.Info().Msgf("[%v] Secret %v.%v - Creating acme client...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		acmeClient, err := acme.NewClient("https://acme-v01.api.letsencrypt.org/directory", letsEncryptUser, acme.RSA2048)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// get dns challenge
		log.Info().Msgf("[%v] Secret %v.%v - Creating cloudflare provider...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		var provider acme.ChallengeProvider
		provider, err = cloudflare.NewDNSProviderCredentials(cfAPIEmail, cfAPIKey)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// clean up acme challenge records in advance
		for _, hostname := range hostnames {
			log.Info().Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
			provider.CleanUp("_acme-challenge."+hostname, "", "123d==")
		}

		// set challenge and provider
		acmeClient.SetChallengeProvider(acme.DNS01, provider)
		acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})

		// get certificate
		log.Info().Msgf("[%v] Secret %v.%v - Obtaining certificate...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		var certificate acme.CertificateResource
		var failures map[string]error
		certificate, failures = acmeClient.ObtainCertificate(hostnames, true, nil, true)

		// clean up acme challenge records afterwards
		for _, hostname := range hostnames {
			log.Info().Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
			provider.CleanUp("_acme-challenge."+hostname, "", "123d==")
		}

		// if obtaining secret failed exit and retry after more than 15 minutes
		if len(failures) > 0 {
			for k, v := range failures {
				log.Error().Msgf("[%s] Could not obtain certificates\n\t%s", k, v.Error())
			}

			err = errors.New("Generating certificates has failed")
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
		secret.Data["ssl.crt"] = certificate.Certificate
		secret.Data["ssl.key"] = certificate.PrivateKey
		secret.Data["ssl.pem"] = bytes.Join([][]byte{certificate.Certificate, certificate.PrivateKey}, []byte{})
		if certificate.IssuerCertificate != nil {
			secret.Data["ssl.issuer.crt"] = certificate.IssuerCertificate
		}

		jsonBytes, err := json.MarshalIndent(certificate, "", "\t")
		if err != nil {
			log.Error().Msgf("[%v] Secret %v.%v - Unable to marshal CertResource for domain %s\n\t%s", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, certificate.Domain, err.Error())
			return status, err
		}
		secret.Data["ssl.json"] = jsonBytes

		// tls keys for ingress object
		secret.Data["tls.crt"] = certificate.Certificate
		secret.Data["tls.key"] = certificate.PrivateKey
		secret.Data["tls.pem"] = bytes.Join([][]byte{certificate.Certificate, certificate.PrivateKey}, []byte{})
		if certificate.IssuerCertificate != nil {
			secret.Data["tls.issuer.crt"] = certificate.IssuerCertificate
		}
		secret.Data["tls.json"] = jsonBytes

		log.Info().Msgf("[%v] Secret %v.%v - Secret has %v data items after writing the certificates...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, len(secret.Data))

		// update secret, because the data and state annotation have changed
		secret, err = kubeClient.CoreV1().UpdateSecret(context.Background(), secret)
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

func processSecret(kubeClient *k8s.Client, secret *apiv1.Secret, initiator string) (status string, err error) {

	status = "failed"

	if &secret != nil && &secret.Metadata != nil && &secret.Metadata.Annotations != nil {

		desiredState := getDesiredSecretState(secret)
		currentState := getCurrentSecretState(secret)

		status, err = makeSecretChanges(kubeClient, secret, initiator, desiredState, currentState)

		return
	}

	status = "skipped"

	return status, nil
}
