package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/cloudflare"

	"github.com/ericchiang/k8s"
	apiv1 "github.com/ericchiang/k8s/api/v1"
)

const annotationLetsEncryptCertificate string = "estafette.io/letsencrypt-certificate"
const annotationLetsEncryptCertificateHostnames string = "estafette.io/letsencrypt-certificate-hostnames"

const annotationLetsEncryptCertificateState string = "estafette.io/letsencrypt-certificate-state"

// KubeLetsEncryptCertificateState represents the state of the secret with respect to Let's Encrypt certificates
type KubeLetsEncryptCertificateState struct {
	Hostnames   string `json:"hostnames"`
	LastRenewed string `json:"lastRenewed"`
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
						err := processSecret(client, secret)
						if err != nil {
							continue
						}
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

				err := processSecret(client, secret)
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

type LetsEncryptUser struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u LetsEncryptUser) GetEmail() string {
	return u.Email
}
func (u LetsEncryptUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u LetsEncryptUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type Account struct {
	Email        string `json:"email"`
	key          crypto.PrivateKey
	Registration *acme.RegistrationResource `json:"registration"`
}

func processSecret(kubeclient *k8s.Client, secret *apiv1.Secret) error {

	cfAPIKey := os.Getenv("CF_API_KEY")
	cfAPIEmail := os.Getenv("CF_API_EMAIL")

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

		fmt.Printf("Certificates in secret %v (namespace %v) have last been renewed %v hours ago at %v (letsEncryptCertificate: %v, letsEncryptCertificateHostnames: %v)...\n", *secret.Metadata.Name, *secret.Metadata.Namespace, durationSinceLastRenewed.Hours(), lastRenewed, letsEncryptCertificate, letsEncryptCertificateHostnames)

		// check if letsencrypt is enabled for this secret, hostnames are set and either the hostnames have changed or the certificate is older than 60 days
		if letsEncryptCertificate == "true" && len(letsEncryptCertificateHostnames) > 0 && (letsEncryptCertificateHostnames != kubeLetsEncryptCertificateState.Hostnames || durationSinceLastRenewed.Hours() > float64(60*24)) {

			fmt.Printf("Certificates in secret %v (namespace %v) are more than 60 days old or hostnames have changed (%v), renewing them with Let's Encrypt...\n", *secret.Metadata.Name, *secret.Metadata.Namespace, letsEncryptCertificateHostnames)

			// load account.json
			fmt.Printf("Loading account.json for secret %v (namespace %v)...\n", *secret.Metadata.Name, *secret.Metadata.Namespace)
			fileBytes, err := ioutil.ReadFile("/account/account.json")
			if err != nil {
				log.Println(err)
				return err
			}
			var letsEncryptUser LetsEncryptUser
			err = json.Unmarshal(fileBytes, &letsEncryptUser)
			if err != nil {
				log.Println(err)
				return err
			}

			// load private key
			fmt.Printf("Loading account.key for secret %v (namespace %v)...\n", *secret.Metadata.Name, *secret.Metadata.Namespace)
			privateKey, err := loadPrivateKey("/account/account.key")
			if err != nil {
				log.Println(err)
				return err
			}
			letsEncryptUser.key = privateKey

			// create letsencrypt acme client
			fmt.Printf("Creating acme client for secret %v (namespace %v)...\n", *secret.Metadata.Name, *secret.Metadata.Namespace)
			client, err := acme.NewClient("https://acme-v01.api.letsencrypt.org/directory", letsEncryptUser, acme.RSA2048)
			if err != nil {
				log.Println(err)
				return err
			}

			// get dns challenge
			fmt.Printf("Creating cloudflare provider for secret %v (namespace %v)...\n", *secret.Metadata.Name, *secret.Metadata.Namespace)
			var provider acme.ChallengeProvider
			provider, err = cloudflare.NewDNSProviderCredentials(cfAPIEmail, cfAPIKey)
			if err != nil {
				log.Println(err)
				return err
			}
			client.SetChallengeProvider(acme.DNS01, provider)
			client.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})

			// clean up acme challenge records in advance
			hostnames := strings.Split(letsEncryptCertificateHostnames, ",")
			for _, hostname := range hostnames {
				provider.CleanUp("_acme-challenge."+hostname, "", "123d==")
			}

			// get certificate
			fmt.Printf("Obtaining certificate for secret %v (namespace %v)...\n", *secret.Metadata.Name, *secret.Metadata.Namespace)
			var certificate acme.CertificateResource
			var failures map[string]error
			certificate, failures = client.ObtainCertificate(hostnames, true, nil)

			// clean up acme challenge records afterwards
			for _, hostname := range hostnames {
				provider.CleanUp("_acme-challenge."+hostname, "", "123d==")
			}

			if len(failures) > 0 {
				for k, v := range failures {
					log.Printf("[%s] Could not obtain certificates\n\t%s", k, v.Error())
				}

				return errors.New("Generating certificates has failed")
			}

			// update the secret
			kubeLetsEncryptCertificateState.Hostnames = letsEncryptCertificateHostnames
			kubeLetsEncryptCertificateState.LastRenewed = time.Now().Format(time.RFC3339)

			fmt.Printf("Updating secret %v (namespace %v) because certificates have changed...\n", *secret.Metadata.Name, *secret.Metadata.Namespace)

			// serialize state and store it in the annotation
			kubeLetsEncryptCertificateStateByteArray, err := json.Marshal(kubeLetsEncryptCertificateState)
			if err != nil {
				log.Println(err)
				return err
			}
			secret.Metadata.Annotations[annotationLetsEncryptCertificateState] = string(kubeLetsEncryptCertificateStateByteArray)

			// store the certificates
			secret.Data["ssl.crt"] = certificate.Certificate
			secret.Data["ssl.key"] = certificate.PrivateKey
			secret.Data["ssl.pem"] = bytes.Join([][]byte{certificate.Certificate, certificate.PrivateKey}, []byte{})

			// update secret, because the data and state annotation have changed
			secret, err = kubeclient.CoreV1().UpdateSecret(context.Background(), secret)
			if err != nil {
				log.Println(err)
				return err
			}
		}
	}

	return nil
}

func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("Unknown private key type.")
}
