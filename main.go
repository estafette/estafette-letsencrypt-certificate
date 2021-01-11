package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
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

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const annotationLetsEncryptCertificate string = "estafette.io/letsencrypt-certificate"
const annotationLetsEncryptCertificateHostnames string = "estafette.io/letsencrypt-certificate-hostnames"
const annotationLetsEncryptCertificateCopyToAllNamespaces string = "estafette.io/letsencrypt-certificate-copy-to-all-namespaces"
const annotationLetsEncryptCertificateLinkedSecret string = "estafette.io/letsencrypt-certificate-linked-secret"
const annotationLetsEncryptCertificateUploadToCloudflare string = "estafette.io/letsencrypt-certificate-upload-to-cloudflare"

const annotationLetsEncryptCertificateState string = "estafette.io/letsencrypt-certificate-state"

// LetsEncryptCertificateState represents the state of the secret with respect to Let's Encrypt certificates
type LetsEncryptCertificateState struct {
	Enabled             string `json:"enabled"`
	Hostnames           string `json:"hostnames"`
	CopyToAllNamespaces bool   `json:"copyToAllNamespaces"`
	UploadToCloudflare  bool   `json:"uploadToCloudflare"`
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

	// set controller Start time to watch only for newly created resources
	controllerStartTime time.Time = time.Now().Local()
)

func init() {
	// metrics have to be registered to be exposed
	prometheus.MustRegister(certificateTotals)
}

func main() {

	// parse command line parameters
	kingpin.Parse()

	// init log format from envvar ESTAFETTE_LOG_FORMAT
	foundation.InitLoggingFromEnv(foundation.NewApplicationInfo(appgroup, app, version, branch, revision, buildDate))

	// init /liveness endpoint
	foundation.InitLiveness()

	// create kubernetes api client
	kubeClientConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal().Err(err)
	}
	// creates the clientset
	kubeClientset, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		log.Fatal().Err(err)
	}

	// create the shared informer factory and use the client to connect to Kubernetes API
	factory := informers.NewSharedInformerFactory(kubeClientset, 0)

	// create a channel to stop the shared informers gracefully
	stopper := make(chan struct{})
	defer close(stopper)

	// handle kubernetes API crashes
	defer k8sruntime.HandleCrash()

	foundation.InitMetrics()

	gracefulShutdown, waitGroup := foundation.InitGracefulShutdownHandling()

	// watch secrets for all namespaces
	go watchSecrets(waitGroup, kubeClientset)

	go listSecrets(waitGroup, kubeClientset)

	// watch namespaces
	watchNamespaces(waitGroup, kubeClientset, factory, stopper)

	foundation.HandleGracefulShutdown(gracefulShutdown, waitGroup)
}

func watchSecrets(waitGroup *sync.WaitGroup, kubeClientset *kubernetes.Clientset) {
	// loop indefinitely
	for {
		log.Info().Msg("Watching secrets for all namespaces...")
		timeoutSeconds := int64(300)

		watcher, err := kubeClientset.CoreV1().Secrets("").Watch(metav1.ListOptions{
			TimeoutSeconds: &timeoutSeconds,
		})

		if err != nil {
			log.Error().Err(err).Msg("WatchSecrets call failed")
		} else {
			// loop indefinitely, unless it errors
			for {
				event, ok := <-watcher.ResultChan()
				if !ok {
					log.Warn().Msg("Watcher for secrets is closed")
					break
				}

				if event.Type == watch.Added || event.Type == watch.Modified {
					secret, ok := event.Object.(*v1.Secret)
					if !ok {
						log.Warn().Msg("Watcher for secrets returns event object of incorrect type")
						break
					}
					waitGroup.Add(1)
					status, err := processSecret(kubeClientset, secret, fmt.Sprintf("watcher:%v", event.Type))
					certificateTotals.With(prometheus.Labels{"namespace": secret.Namespace, "status": status, "initiator": "watcher", "type": "secret"}).Inc()
					waitGroup.Done()

					if err != nil {
						log.Error().Err(err).Msgf("Processing secret %v.%v failed", secret.Name, secret.Namespace)
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

func listSecrets(waitGroup *sync.WaitGroup, kubeClientset *kubernetes.Clientset) {
	// loop indefinitely
	for {
		// get secrets for all namespaces
		log.Info().Msg("Listing secrets for all namespaces...")
		secrets, err := kubeClientset.CoreV1().Secrets("").List(metav1.ListOptions{})
		if err != nil {
			log.Error().Err(err).Msg("ListSecrets call failed")
		}
		log.Info().Msgf("Cluster has %v secrets", len(secrets.Items))

		// loop all secrets
		for _, secret := range secrets.Items {
			waitGroup.Add(1)
			status, err := processSecret(kubeClientset, &secret, "poller")
			certificateTotals.With(prometheus.Labels{"namespace": secret.Namespace, "status": status, "initiator": "poller", "type": "secret"}).Inc()
			waitGroup.Done()

			if err != nil {
				log.Error().Err(err).Msgf("Processing secret %v.%v failed", secret.Name, secret.Namespace)
				continue
			}
		}

		// sleep random time around 900 seconds
		sleepTime := applyJitter(900)
		log.Info().Msgf("Sleeping for %v seconds...", sleepTime)
		time.Sleep(time.Duration(sleepTime) * time.Second)
	}
}

func watchNamespaces(waitGroup *sync.WaitGroup, kubeClientset *kubernetes.Clientset, factory informers.SharedInformerFactory, stopper chan struct{}) {
	log.Info().Msg("Watching for new namespaces...")

	namespacesInformer := factory.Core().V1().Namespaces().Informer()
	namespacesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			namespace, ok := obj.(*v1.Namespace)
			if !ok {
				log.Warn().Msg("Watcher for namespaces returns event object of incorrect type")
				return
			}
			// compare CreationTimestamp and controllerStartTime and act only on latest events
			isNewNamespace := namespace.CreationTimestamp.Sub(controllerStartTime).Seconds() > 0
			if isNewNamespace {

				log.Info().Msg("Listing secrets with 'copyToAllNamespaces' for all namespaces...")

				secrets, err := kubeClientset.CoreV1().Secrets("").List(metav1.ListOptions{})
				if err != nil {
					log.Error().Err(err).Msgf("[%v] ListSecrets call failed", "ns-watcher:ADDED")
				} else {
					// loop all secrets
					for _, secret := range secrets.Items {
						copyToAllNamespacesValue, ok := secret.Annotations[annotationLetsEncryptCertificateCopyToAllNamespaces]
						if ok {
							shouldCopyToAllNamespaces, err := strconv.ParseBool(copyToAllNamespacesValue)
							if err != nil {
								log.Error().Err(err)
								continue
							}
							if shouldCopyToAllNamespaces {
								waitGroup.Add(1)
								err = copySecretToNamespace(kubeClientset, &secret, namespace, "ns-watcher:ADDED")
								waitGroup.Done()

								if err != nil {
									log.Error().Err(err)
									continue
								}
							}
						}
					}
				}
			}

		},
	})

	go namespacesInformer.Run(stopper)
}

func applyJitter(input int) (output int) {

	deviation := int(0.25 * float64(input))

	return input - deviation + r.Intn(2*deviation)
}

func getDesiredSecretState(secret *v1.Secret) (state LetsEncryptCertificateState) {

	var ok bool

	// get annotations or set default value
	state.Enabled, ok = secret.Annotations[annotationLetsEncryptCertificate]
	if !ok {
		state.Enabled = "false"
	}
	state.Hostnames, ok = secret.Annotations[annotationLetsEncryptCertificateHostnames]
	if !ok {
		state.Hostnames = ""
	}
	copyToAllNamespacesValue, ok := secret.Annotations[annotationLetsEncryptCertificateCopyToAllNamespaces]
	if ok {
		b, err := strconv.ParseBool(copyToAllNamespacesValue)
		if err == nil {
			state.CopyToAllNamespaces = b
		}
	}
	uploadToCloudflare, ok := secret.Annotations[annotationLetsEncryptCertificateUploadToCloudflare]
	if ok {
		b, err := strconv.ParseBool(uploadToCloudflare)
		if err == nil {
			state.UploadToCloudflare = b
		}
	}

	return
}

func getCurrentSecretState(secret *v1.Secret) (state LetsEncryptCertificateState) {

	// get state stored in annotations if present or set to empty struct
	letsEncryptCertificateStateString, ok := secret.Annotations[annotationLetsEncryptCertificateState]
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

func makeSecretChanges(kubeClientset *kubernetes.Clientset, secret *v1.Secret, initiator string, desiredState, currentState LetsEncryptCertificateState) (status string, err error) {

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

		log.Info().Msgf("[%v] Secret %v.%v - Certificates are more than 60 days old or hostnames have changed (%v), renewing them with Let's Encrypt...", initiator, secret.Name, secret.Namespace, desiredState.Hostnames)

		// 'lock' the secret for 15 minutes by storing the last attempt timestamp to prevent hitting the rate limit if the Let's Encrypt call fails and to prevent the watcher and the fallback polling to operate on the secret at the same time
		currentState.LastAttempt = time.Now().Format(time.RFC3339)

		// serialize state and store it in the annotation
		letsEncryptCertificateStateByteArray, err := json.Marshal(currentState)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}
		secret.Annotations[annotationLetsEncryptCertificateState] = string(letsEncryptCertificateStateByteArray)

		// update secret, with last attempt; this will fire an event for the watcher, but this shouldn't lead to any action because storing the last attempt locks the secret for 15 minutes
		_, err = kubeClientset.CoreV1().Secrets(secret.Namespace).Update(secret)
		if err != nil {
			log.Error().Err(err).Msgf("[%v] Secret %v.%v - Updating secret state has failed", initiator, secret.Name, secret.Namespace)
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
		log.Info().Msgf("[%v] Secret %v.%v - Loading account.json...", initiator, secret.Name, secret.Namespace)
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
		log.Info().Msgf("[%v] Secret %v.%v - Loading account.key...", initiator, secret.Name, secret.Namespace)
		privateKey, err := loadPrivateKey("/account/account.key")
		if err != nil {
			log.Error().Err(err)
			return status, err
		}
		letsEncryptUser.key = privateKey

		log.Info().Msgf("[%v] Secret %v.%v - Creating lego config...", initiator, secret.Name, secret.Namespace)
		config := lego.NewConfig(&letsEncryptUser)

		// create letsencrypt lego client
		log.Info().Msgf("[%v] Secret %v.%v - Creating lego client...", initiator, secret.Name, secret.Namespace)
		legoClient, err := lego.NewClient(config)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// get dns challenge
		log.Info().Msgf("[%v] Secret %v.%v - Creating cloudflare provider...", initiator, secret.Name, secret.Namespace)
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
		// 	log.Info().Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v...", initiator, secret.Name, secret.Namespace, hostname)
		// 	err = cloudflareProvider.CleanUp(hostname, "", "123d==")
		// 	if err != nil {
		// 		log.Info().Err(err).Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v failed", initiator, secret.Name, secret.Namespace, hostname)
		// 	}
		// }

		// set challenge provider
		legoClient.Challenge.SetDNS01Provider(cloudflareProvider)

		// get certificate
		log.Info().Msgf("[%v] Secret %v.%v - Obtaining certificate...", initiator, secret.Name, secret.Namespace)
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
		// 	log.Info().Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v...", initiator, secret.Name, secret.Namespace, hostname)
		// 	err = cloudflareProvider.CleanUp(hostname, "", "123d==")
		// 	if err != nil {
		// 		log.Info().Err(err).Msgf("[%v] Secret %v.%v - Cleaning up TXT record _acme-challenge.%v failed", initiator, secret.Name, secret.Namespace, hostname)
		// 	}
		// }

		// reload secret to avoid object has been modified error
		secret, err = kubeClientset.CoreV1().Secrets(secret.Namespace).Get(secret.Name, metav1.GetOptions{})
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		// update the secret
		currentState = desiredState
		currentState.LastRenewed = time.Now().Format(time.RFC3339)

		log.Info().Msgf("[%v] Secret %v.%v - Updating secret because new certificates have been obtained...", initiator, secret.Name, secret.Namespace)

		// serialize state and store it in the annotation
		letsEncryptCertificateStateByteArray, err = json.Marshal(currentState)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}
		secret.Annotations[annotationLetsEncryptCertificateState] = string(letsEncryptCertificateStateByteArray)

		// store the certificates
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}

		log.Info().Msgf("[%v] Secret %v.%v - Secret has %v data items before writing the certificates...", initiator, secret.Name, secret.Namespace, len(secret.Data))

		// ssl keys
		secret.Data["ssl.crt"] = certificates.Certificate
		secret.Data["ssl.key"] = certificates.PrivateKey
		secret.Data["ssl.pem"] = bytes.Join([][]byte{certificates.Certificate, certificates.PrivateKey}, []byte{})
		if certificates.IssuerCertificate != nil {
			secret.Data["ssl.issuer.crt"] = certificates.IssuerCertificate
		}

		jsonBytes, err := json.MarshalIndent(certificates, "", "\t")
		if err != nil {
			log.Error().Msgf("[%v] Secret %v.%v - Unable to marshal CertResource for domain %s\n\t%s", initiator, secret.Name, secret.Namespace, certificates.Domain, err.Error())
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

		log.Info().Msgf("[%v] Secret %v.%v - Secret has %v data items after writing the certificates...", initiator, secret.Name, secret.Namespace, len(secret.Data))

		// update secret, because the data and state annotation have changed
		_, err = kubeClientset.CoreV1().Secrets(secret.Namespace).Update(secret)
		if err != nil {
			log.Error().Err(err)
			return status, err
		}

		status = "succeeded"

		log.Info().Msgf("[%v] Secret %v.%v - Certificates have been stored in secret successfully...", initiator, secret.Name, secret.Namespace)

		if desiredState.CopyToAllNamespaces {
			// copy to other namespaces if annotation is set to true
			err = copySecretToAllNamespaces(kubeClientset, secret, initiator)
			if err != nil {
				return status, err
			}
		}

		if desiredState.UploadToCloudflare {
			// upload certificate to cloudflare for each hostname
			err = uploadToCloudflare(desiredState.Hostnames, certificates.Certificate, certificates.PrivateKey)
			if err != nil {
				return status, err
			}
		}

		return status, nil
	}

	status = "skipped"

	return status, nil
}

func copySecretToAllNamespaces(kubeClientset *kubernetes.Clientset, secret *v1.Secret, initiator string) (err error) {

	// get all namespaces
	namespaces, err := kubeClientset.CoreV1().Namespaces().List(metav1.ListOptions{})

	// loop namespaces
	for _, ns := range namespaces.Items {
		err := copySecretToNamespace(kubeClientset, secret, &ns, initiator)
		if err != nil {
			return err
		}
	}

	return nil
}

func copySecretToNamespace(kubeClientset *kubernetes.Clientset, secret *v1.Secret, namespace *v1.Namespace, initiator string) error {

	if namespace.Name == secret.Namespace || namespace.Status.Phase != v1.NamespaceActive {
		return nil
	}

	log.Info().Msgf("[%v] Secret %v.%v - Copying secret to namespace %v...", initiator, secret.Name, secret.Namespace, namespace.Name)

	// check if secret with same name already exists
	secretInNamespace, err := kubeClientset.CoreV1().Secrets(namespace.Name).Get(secret.Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		// doesn't exist, create new secret
		secretInNamespace = &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secret.Name,
				Namespace: namespace.Name,
				Labels:    secret.Labels,
				Annotations: map[string]string{
					annotationLetsEncryptCertificateLinkedSecret: fmt.Sprintf("%v/%v", secret.Namespace, secret.Name),
					annotationLetsEncryptCertificateState:        secret.Annotations[annotationLetsEncryptCertificateState],
				},
			},
			Data: secret.Data,
		}

		_, err = kubeClientset.CoreV1().Secrets(namespace.Name).Create(secretInNamespace)
		if err != nil {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}

	// already exists
	log.Info().Msgf("[%v] Secret %v.%v - Already exists in namespace %v, updating data...", initiator, secret.Name, secret.Namespace, namespace.Name)

	// update data in secret
	secretInNamespace.Data = secret.Data
	secretInNamespace.Annotations[annotationLetsEncryptCertificateState] = secret.Annotations[annotationLetsEncryptCertificateState]

	_, err = kubeClientset.CoreV1().Secrets(namespace.Name).Update(secretInNamespace)
	if err != nil {
		return err
	}

	return nil
}

func isEventExist(kubeClientset *kubernetes.Clientset, namespace string, name string) (*v1.Event, string, error) {
	event, err := kubeClientset.CoreV1().Events(namespace).Get(name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, "not found", err
	}
	if err != nil {
		log.Error().Msgf("Event %v.%v - Getting event has an error.\n\t%s", name, namespace, err.Error())
		return nil, "error", err
	}

	return event, "found", nil
}

func postEventAboutStatus(kubeClientset *kubernetes.Clientset, secret *v1.Secret, eventType string, action string, reason string, message string, kind string, reportingController string, reportingInstance string) (err error) {
	now := time.Now().UTC()
	count := int32(1)
	eventName := fmt.Sprintf("%v-%v", secret.Name, action)
	eventSource := os.Getenv("HOSTNAME")
	eventResp, exist, err := isEventExist(kubeClientset, secret.Namespace, eventName)

	if exist == "error" {
		return err
	}

	if exist == "found" {
		count = eventResp.Count + 1
		eventResp.Type = eventType
		eventResp.Action = action
		eventResp.Reason = reason
		eventResp.Message = message
		eventResp.Count = count
		eventResp.LastTimestamp = metav1.NewTime(now)
		_, err = kubeClientset.CoreV1().Events(secret.Namespace).Update(eventResp)

		if err != nil {
			log.Error().Msgf("Event %v.%v - Updating Event has an error.\n\t%s", eventResp.Name, eventResp.Namespace, err.Error())
			return err
		}

		log.Info().Msgf("Event %v.%v - has been updated successfully...", eventResp.Name, eventResp.Namespace)
		return
	}

	event := &v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:              eventName,
			Namespace:         secret.Namespace,
			CreationTimestamp: metav1.NewTime(now),
			Labels:            secret.Labels,
		},
		FirstTimestamp: metav1.NewTime(now),
		LastTimestamp:  metav1.NewTime(now),
		Type:           eventType,
		Action:         action,
		Reason:         reason,
		Message:        message,
		Count:          count,
		Source: v1.EventSource{
			Component: eventSource,
		},
		InvolvedObject: v1.ObjectReference{
			APIVersion:      secret.APIVersion,
			Kind:            kind,
			Namespace:       secret.Namespace,
			Name:            secret.Name,
			ResourceVersion: secret.ResourceVersion,
			UID:             secret.UID,
		},
		EventTime:           metav1.NewMicroTime(now),
		ReportingController: reportingController,
		ReportingInstance:   reportingInstance,
	}

	_, err = kubeClientset.CoreV1().Events(event.Namespace).Create(event)
	if err != nil {
		log.Error().Msgf("Event %v.%v - Creating Event has an error. %s", event.Name, event.Namespace, err.Error())
		return err
	}

	log.Info().Msgf("Event %v.%v - has been created successfully...", event.Name, event.Namespace)
	return
}

func processSecret(kubeClientset *kubernetes.Clientset, secret *v1.Secret, initiator string) (status string, err error) {
	status = "failed"

	if secret != nil {

		desiredState := getDesiredSecretState(secret)
		currentState := getCurrentSecretState(secret)
		status, err = makeSecretChanges(kubeClientset, secret, initiator, desiredState, currentState)

		if err != nil {
			log.Error().Err(err).Msgf("[%v] Secret %v.%v - Error occurred...", initiator, secret.Name, secret.Namespace)
		}

		if status == "failed" {
			err = postEventAboutStatus(kubeClientset, secret, "Warning", strings.Title(status), "FailedObtain", fmt.Sprintf("Certificate for secret %v obtaining failed", secret.Name), "Secret", "estafette.io/letsencrypt-certificate", os.Getenv("HOSTNAME"))
			return
		}
		if status == "succeeded" {
			err = postEventAboutStatus(kubeClientset, secret, "Normal", strings.Title(status), "SuccessfulObtain", fmt.Sprintf("Certificate for secret %v has been obtained succesfully", secret.Name), "Secret", "estafette.io/letsencrypt-certificate", os.Getenv("HOSTNAME"))
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

func uploadToCloudflare(hostnames string, certificate, privateKey []byte) (err error) {
	// init cf
	authentication := APIAuthentication{Key: *cfAPIKey, Email: *cfAPIEmail}
	cf := NewCloudflare(authentication)

	// loop hostnames
	hostnameList := strings.Split(hostnames, ",")
	for _, hostname := range hostnameList {
		_, err := cf.UpsertSSLConfigurationByDNSName(hostname, string(certificate), string(privateKey))
		if err != nil {
			return err
		}
	}

	return nil
}
