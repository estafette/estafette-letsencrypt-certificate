package main

import (
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/ericchiang/k8s"
	apiv1 "github.com/ericchiang/k8s/api/v1"
	"github.com/xenolf/lego/acme"
)

const annotationLetsEncryptCertificate string = "estafette.io/letsencrypt-certificate"
const annotationLetsEncryptCertificateHostnames string = "estafette.io/letsencrypt-certificate-hostnames"

const annotationLetsEncryptCertificateState string = "estafette.io/letsencrypt-certificate-state"

// KubeLetsEncryptCertificateState represents the state of the secret with respect to Let's Encrypt certificates
type KubeLetsEncryptCertificateState struct {
	Hostnames   string `json:"hostnames"`
	LastRenewed string `json:"lastRenewed"`
}

type MyUser struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

var (
	addr = flag.String("listen-address", ":9101", "The address to listen on for HTTP requests.")

	// seed random number
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func main() {

	// create cloudflare api client
	cfAPIKey := os.Getenv("CF_API_KEY")
	if cfAPIKey == "" {
		log.Fatal("CF_API_KEY is required. Please set CF_API_KEY environment variable to your Cloudflare API key.")
	}
	cfAPIEmail := os.Getenv("CF_API_EMAIL")
	if cfAPIEmail == "" {
		log.Fatal("CF_API_EMAIL is required. Please set CF_API_KEY environment variable to your Cloudflare API email.")
	}

	// create kubernetes api client
	client, err := k8s.NewInClusterClient()
	if err != nil {
		log.Fatal(err)
	}

	// watch secrets for all namespaces
	go func() {
		// loop indefinitely
		for {
			fmt.Println("Watching secrets for all namespaces...")
			watcher, err := client.CoreV1().WatchSecrets(context.Background(), k8s.AllNamespaces)
			if err != nil {
				log.Println(err)
			} else {
				// loop indefinitely, unless it errors
				for {
					event, secret, err := watcher.Next()
					if err != nil {
						log.Println(err)
						break
					}

					if *event.Type == k8s.EventAdded || *event.Type == k8s.EventModified {
						fmt.Printf("Secret %v (namespace %v) has event of type %v, processing it...\n", *secret.Metadata.Name, *secret.Metadata.Namespace, *event.Type)
						processSecret(client, secret)
					} else {
						fmt.Printf("Secret %v (namespace %v) has event of type %v, skipping it...\n", *secret.Metadata.Name, *secret.Metadata.Namespace, *event.Type)
					}
				}
			}

			// sleep random time between 22 and 37 seconds
			sleepTime := applyJitter(30)
			fmt.Printf("Sleeping for %v seconds...\n", sleepTime)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}()

	// loop indefinitely
	for {

		// get secrets for all namespaces
		fmt.Println("Listing secrets for all namespaces...")
		secrets, err := client.CoreV1().ListSecrets(context.Background(), k8s.AllNamespaces)
		if err != nil {
			log.Println(err)
		}
		fmt.Printf("Cluster has %v secrets\n", len(secrets.Items))

		// loop all secrets
		if secrets != nil && secrets.Items != nil {
			for _, secret := range secrets.Items {

				processSecret(client, secret)
				if err != nil {
					continue
				}
			}
		}

		// sleep random time between 225 and 375 seconds
		sleepTime := applyJitter(300)
		fmt.Printf("Sleeping for %v seconds...\n", sleepTime)
		time.Sleep(time.Duration(sleepTime) * time.Second)
	}
}

func applyJitter(input int) (output int) {

	deviation := int(0.25 * float64(input))

	return input - deviation + r.Intn(2*deviation)
}

func processSecret(kubeclient *k8s.Client, secret *apiv1.Secret) error {

	if &secret != nil && &secret.Metadata != nil && &secret.Metadata.Annotations != nil {

		// get annotations or set default value
		letsEncryptCertificate, ok := secret.Metadata.Annotations[annotationLetsEncryptCertificate]
		if !ok {
			letsEncryptCertificate = "false"
		}
		letsEncryptCertificateHostnames, ok := secret.Metadata.Annotations[annotationLetsEncryptCertificateHostnames]
		if !ok {
			letsEncryptCertificateHostnames = ""
		}

		// get state stored in annotations if present or set to empty struct
		var kubeLetsEncryptCertificateState KubeLetsEncryptCertificateState
		kubeLetsEncryptCertificateStateString, ok := secret.Metadata.Annotations[annotationLetsEncryptCertificateState]
		if err := json.Unmarshal([]byte(kubeLetsEncryptCertificateStateString), &kubeLetsEncryptCertificateState); err != nil {
			// couldn't deserialize, setting to default struct
			kubeLetsEncryptCertificateState = KubeLetsEncryptCertificateState{}
		}

		// parse last renewed time from state
		lastRenewed := time.Time{}
		if kubeLetsEncryptCertificateState.LastRenewed != "" {
			var err error
			lastRenewed, err = time.Parse(time.RFC3339, kubeLetsEncryptCertificateState.LastRenewed)
			if err != nil {
				lastRenewed = time.Time{}
			}
		}

		durationSinceLastRenewed := time.Since(lastRenewed)

		if letsEncryptCertificate == "true" && (letsEncryptCertificateHostnames != kubeLetsEncryptCertificateState.Hostnames || durationSinceLastRenewed.Hours() > float64(60*24)) {

			updateSecret := false

			// generate or renew certificates

			// Create a user. New accounts need an email and private key to start.
			const rsaKeySize = 2048
			privateKey, err := rsa.GenerateKey(cryptorand.Reader, rsaKeySize)
			if err != nil {
				log.Fatal(err)
			}
			myUser := MyUser{
				Email: "you@yours.com",
				key:   privateKey,
			}

			client, err := acme.NewClient("https://acme-v01.api.letsencrypt.org/directory", &myUser, acme.RSA2048)
			if err != nil {
				log.Fatal(err)
			}

			// New users will need to register
			reg, err := client.Register()
			if err != nil {
				log.Fatal(err)
			}
			myUser.Registration = reg

			// SAVE THE USER.

			// The client has a URL to the current Let's Encrypt Subscriber
			// Agreement. The user will need to agree to it.
			err = client.AgreeToTOS()
			if err != nil {
				log.Fatal(err)
			}

			// The acme library takes care of completing the challenges to obtain the certificate(s).
			// The domains must resolve to this machine or you have to use the DNS challenge.
			bundle := false
			certificates, failures := client.ObtainCertificate([]string{"mydomain.com"}, bundle, privateKey)
			if len(failures) > 0 {
				log.Fatal(failures)
			}

			// Each certificate comes back with the cert bytes, the bytes of the client's
			// private key, and a certificate URL. SAVE THESE TO DISK.
			fmt.Printf("%#v\n", certificates)

			if updateSecret {

				// if any state property changed make sure to update all
				kubeLetsEncryptCertificateState.Hostnames = letsEncryptCertificateHostnames
				kubeLetsEncryptCertificateState.LastRenewed = time.Now().Format(time.RFC3339)

				fmt.Printf("Updating secret %v (namespace %v) because state has changed...\n", *secret.Metadata.Name, *secret.Metadata.Namespace)

				// serialize state and store it in the annotation
				kubeLetsEncryptCertificateStateByteArray, err := json.Marshal(kubeLetsEncryptCertificateState)
				if err != nil {
					log.Println(err)
					return err
				}
				secret.Metadata.Annotations[annotationLetsEncryptCertificateState] = string(kubeLetsEncryptCertificateStateByteArray)

				// update secret, because the state annotations have changed
				secret, err = kubeclient.CoreV1().UpdateSecret(context.Background(), secret)
				if err != nil {
					log.Println(err)
					return err
				}

			}
		}
	}

	return nil
}
