package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kingpin"
	foundation "github.com/estafette/estafette-foundation"
	"github.com/rs/zerolog/log"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/providers/dns/cloudflare"

	"github.com/ericchiang/k8s"
	corev1 "github.com/ericchiang/k8s/apis/core/v1"
	metav1 "github.com/ericchiang/k8s/apis/meta/v1"
)

const annotationLetsEncryptCertificate string = "estafette.io/letsencrypt-certificate"
const annotationLetsEncryptCertificateHostnames string = "estafette.io/letsencrypt-certificate-hostnames"
const annotationLetsEncryptCertificateCopyToAllNamespaces string = "estafette.io/letsencrypt-certificate-copy-to-all-namespaces"
const annotationLetsEncryptCertificateLinkedSecret string = "estafette.io/letsencrypt-certificate-linked-secret"

const annotationLetsEncryptCertificateState string = "estafette.io/letsencrypt-certificate-state"

// LetsEncryptCertificateState represents the state of the secret with respect to Let's Encrypt certificates
type LetsEncryptCertificateState struct {
	Enabled             string `json:"enabled"`
	Hostnames           string `json:"hostnames"`
	CopyToAllNamespaces bool   `json:"copyToAllNamespaces"`
	LastRenewed         string `json:"lastRenewed"`
	LastAttempt         string `json:"lastAttempt"`
}

var (
	appgroup  string
	app       string
	version   string
	branch    string
	revision  string
	buildDate string
	goVersion = runtime.Version()
)

var (
	cfAPIKey   = kingpin.Flag("cloudflare-api-key", "The API key to connect to cloudflare.").Envar("CF_API_KEY").Required().String()
	cfAPIEmail = kingpin.Flag("cloudflare-api-email", "The API email address to connect to cloudflare.").Envar("CF_API_EMAIL").Required().String()

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
	k8s.Register("", "v1", "events", true, &corev1.Event{})
	k8s.RegisterList("", "v1", "events", true, &corev1.EventList{})
}

func main() {

	// parse command line parameters
	kingpin.Parse()

	// init log format from envvar ESTAFETTE_LOG_FORMAT
	foundation.InitLoggingFromEnv(foundation.NewApplicationInfo(appgroup, app, version, branch, revision, buildDate))

	// init /liveness endpoint
	foundation.InitLiveness()

	// create kubernetes api client
	client, err := k8s.NewInClusterClient()
	if err != nil {
		log.Fatal().Err(err)
	}

	foundation.InitMetrics()

	gracefulShutdown, waitGroup := foundation.InitGracefulShutdownHandling()

	// watch secrets for all namespaces
	go watchSecrets(waitGroup, client)

	go listSecrets(waitGroup, client)

	foundation.HandleGracefulShutdown(gracefulShutdown, waitGroup)
}

func watchSecrets(waitGroup *sync.WaitGroup, client *k8s.Client) {
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
}

func listSecrets(waitGroup *sync.WaitGroup, client *k8s.Client) {
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
	copyToAllNamespacesValue, ok := secret.Metadata.Annotations[annotationLetsEncryptCertificateCopyToAllNamespaces]
	if ok {
		b, err := strconv.ParseBool(copyToAllNamespacesValue)
		if err == nil {
			state.CopyToAllNamespaces = b
		}
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
		cloudflareConfig.AuthEmail = *cfAPIEmail
		cloudflareConfig.AuthKey = *cfAPIKey
		cloudflareConfig.PropagationTimeout = 10 * time.Minute

		cloudflareProvider, err := cloudflare.NewDNSProviderConfig(cloudflareConfig)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// clean up acme challenge records in advance
		// for _, hostname := range hostnames {
		// 	log.Info().Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
		// 	err = cloudflareProvider.CleanUp(hostname, "", "123d==")
		// 	if err != nil {
		// 		log.Info().Err(err).Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v failed", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
		// 	}
		// }

		// set challenge provider
		legoClient.Challenge.SetDNS01Provider(cloudflareProvider)

		// get certificate
		log.Info().Msgf("[%v] Secret %v.%v - Obtaining certificate...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		request := certificate.ObtainRequest{
			Domains: hostnames,
			Bundle:  true,
		}
		certificates, err := legoClient.Certificate.Obtain(request)

		// if obtaining secret failed exit and retry after more than 15 minutes
		if err != nil {
			log.Error().Err(err).Msgf("Could not obtain certificates for domains %v due to error", hostnames)
			return status, err
		}
		if certificates == nil {
			log.Error().Msgf("Could not obtain certificates for domains %v, certificates are empty", hostnames)
			return status, err
		}

		// clean up acme challenge records afterwards
		// for _, hostname := range hostnames {
		// 	log.Info().Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
		// 	err = cloudflareProvider.CleanUp(hostname, "", "123d==")
		// 	if err != nil {
		// 		log.Info().Err(err).Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v failed", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, hostname)
		// 	}
		// }

		// reload secret to avoid object has been modified error
		err = kubeClient.Get(context.Background(), *secret.Metadata.Namespace, *secret.Metadata.Name, secret)
		if err != nil {
			log.Error().Err(err)
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

		if desiredState.CopyToAllNamespaces {
			// copy to other namespaces if annotation is set to true
			err = copySecretToAllNamespaces(kubeClient, secret, initiator)
			if err != nil {
				return status, err
			}
		}

		return status, nil
	}

	status = "skipped"

	return status, nil
}

func copySecretToAllNamespaces(kubeClient *k8s.Client, secret *corev1.Secret, initiator string) (err error) {

	// get all namespaces
	var namespaces corev1.NamespaceList
	err = kubeClient.List(context.Background(), k8s.AllNamespaces, &namespaces)

	// loop namespaces
	for _, ns := range namespaces.GetItems() {
		err := copySecretToNamespace(kubeClient, secret, ns, initiator)
		if err != nil {
			return err
		}
	}

	return nil
}

func copySecretToNamespace(kubeClient *k8s.Client, secret *corev1.Secret, namespace *corev1.Namespace, initiator string) error {

	nsName := namespace.GetMetadata().GetName()
	if nsName == secret.Metadata.GetNamespace() || namespace.GetStatus().GetPhase() != "Active" {
		return nil
	}

	log.Info().Msgf("[%v] Secret %v.%v - Copying secret to namespace %v...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, nsName)

	// check if secret with same name already exists
	var secretInNamespace corev1.Secret
	err := kubeClient.Get(context.Background(), nsName, secret.Metadata.GetName(), &secretInNamespace)

	if apiErr, ok := err.(*k8s.APIError); ok {
		if apiErr.Code == http.StatusNotFound {
			// doesn't exist, create new secret
			secretInNamespace = corev1.Secret{
				Metadata: &metav1.ObjectMeta{
					Name:      secret.Metadata.Name,
					Namespace: &nsName,
					Labels:    secret.Metadata.GetLabels(),
					Annotations: map[string]string{
						annotationLetsEncryptCertificateLinkedSecret: fmt.Sprintf("%v/%v", secret.Metadata.GetNamespace(), secret.Metadata.GetName()),
						annotationLetsEncryptCertificateState:        secret.GetMetadata().GetAnnotations()[annotationLetsEncryptCertificateState],
					},
				},
				Data: secret.GetData(),
			}

			err = kubeClient.Create(context.Background(), &secretInNamespace)
			if err != nil {
				return err
			}
			return nil
		}

		// other type of error
		return err
	}

	// already exists
	log.Info().Msgf("[%v] Secret %v.%v - Already exists in namespace %v, updating data...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace, nsName)

	// update data in secret
	secretInNamespace.Data = secret.GetData()
	secretInNamespace.Metadata.Annotations[annotationLetsEncryptCertificateState] = secret.GetMetadata().GetAnnotations()[annotationLetsEncryptCertificateState]

	err = kubeClient.Update(context.Background(), &secretInNamespace)
	if err != nil {
		return err
	}

	return nil
}

func isEventExist(kubeClient *k8s.Client, namespace string, name string, event *corev1.Event) (exist string, err error) {
	err = kubeClient.Get(context.Background(), namespace, name, event)

	if apiErr, ok := err.(*k8s.APIError); ok {
		if apiErr.Code == http.StatusNotFound {
			return "not found", err
		}

		log.Error().Msgf("Event %v.%v - Getting event has an error.\n\t%s", name, namespace, err.Error())
		return "error", err
	}

	return "found", nil
}

func postEventAboutStatus(kubeClient *k8s.Client, secret *corev1.Secret, eventType string, action string, reason string, message string, kind string, reportingController string, reportingInstance string) (err error) {
	now := time.Now().UTC()
	secs := int64(now.Unix())
	count := int32(1)
	eventName := fmt.Sprintf("%v-%v", *secret.Metadata.Name, action)
	eventSource := os.Getenv("HOSTNAME")
	var eventResp corev1.Event
	var exist string
	exist, err = isEventExist(kubeClient, *secret.Metadata.Namespace, eventName, &eventResp)

	if exist == "error" {
		return err
	}

	if exist == "found" {
		count = *eventResp.Count + 1
		eventResp.Type = &eventType
		eventResp.Action = &action
		eventResp.Reason = &reason
		eventResp.Message = &message
		eventResp.Count = &count
		eventResp.LastTimestamp.Seconds = &secs
		err = kubeClient.Update(context.Background(), &eventResp)

		if err != nil {
			log.Error().Msgf("Event %v.%v - Updating Event has an error.\n\t%s", *eventResp.Metadata.Name, *eventResp.Metadata.Namespace, err.Error())
			return err
		}

		log.Info().Msgf("Event %v.%v - has been updated successfully...", *eventResp.Metadata.Name, *eventResp.Metadata.Namespace)
		return
	}

	event := &corev1.Event{
		Metadata: &metav1.ObjectMeta{
			Name:      &eventName,
			Namespace: secret.Metadata.Namespace,
			CreationTimestamp: &metav1.Time{
				Seconds: &secs,
			},
			Labels: secret.Metadata.Labels,
		},
		FirstTimestamp: &metav1.Time{
			Seconds: &secs,
		},
		LastTimestamp: &metav1.Time{
			Seconds: &secs,
		},
		Type:    &eventType,
		Action:  &action,
		Reason:  &reason,
		Message: &message,
		Count:   &count,
		Source: &corev1.EventSource{
			Component: &eventSource,
		},
		InvolvedObject: &corev1.ObjectReference{
			Namespace: secret.Metadata.Namespace,
			Kind:      &kind,
		},
		EventTime: &metav1.MicroTime{
			Seconds: &secs,
		},
		ReportingComponent: &reportingController,
		ReportingInstance:  &reportingInstance,
	}

	err = kubeClient.Create(context.Background(), event)

	if err != nil {
		log.Error().Msgf("Event %v.%v - Creating Event has an error. %s", *event.Metadata.Name, *event.Metadata.Namespace, err.Error())
		return err
	}

	log.Info().Msgf("Event %v.%v - has been created successfully...", *event.Metadata.Name, *event.Metadata.Namespace)
	return
}

func processSecret(kubeClient *k8s.Client, secret *corev1.Secret, initiator string) (status string, err error) {
	status = "failed"

	if &secret != nil && &secret.Metadata != nil && &secret.Metadata.Annotations != nil {

		desiredState := getDesiredSecretState(secret)
		currentState := getCurrentSecretState(secret)
		status, err = makeSecretChanges(kubeClient, secret, initiator, desiredState, currentState)

		if err != nil {
			log.Error().Err(err).Msgf("[%v] Secret %v.%v - Error occurred...", initiator, *secret.Metadata.Name, *secret.Metadata.Namespace)
		}

		if status == "failed" {
			err = postEventAboutStatus(kubeClient, secret, "Warning", strings.Title(status), "FailedObtain", fmt.Sprintf("Certificate for secret %v obtaining failed", *secret.Metadata.Name), "Secret", "estafette.io/letsencrypt-certificate", os.Getenv("HOSTNAME"))
			return
		}
		if status == "succeeded" {
			err = postEventAboutStatus(kubeClient, secret, "Normal", strings.Title(status), "SuccessfulObtain", fmt.Sprintf("Certificate for secret %v has been obtained succesfully", *secret.Metadata.Name), "Secret", "estafette.io/letsencrypt-certificate", os.Getenv("HOSTNAME"))
			return
		}
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
