package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// Zone represents a zone in Cloudflare (https://api.cloudflare.com/#zone-list-zones).
type Zone struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	DevMode           int       `json:"development_mode"`
	OriginalNS        []string  `json:"original_name_servers"`
	OriginalRegistrar string    `json:"original_registrar"`
	OriginalDNSHost   string    `json:"original_dnshost"`
	CreatedOn         time.Time `json:"created_on"`
	ModifiedOn        time.Time `json:"modified_on"`
	NameServers       []string  `json:"name_servers"`
	Permissions       []string  `json:"permissions"`
	Status            string    `json:"status"`
	Paused            bool      `json:"paused"`
	Type              string    `json:"type"`
	Host              struct {
		Name    string
		Website string
	} `json:"host"`
	VanityNS    []string `json:"vanity_name_servers"`
	Betas       []string `json:"betas"`
	DeactReason string   `json:"deactivation_reason"`
}

// APIAuthentication contains the email address and api key to authenticate a request to the cloudflare api.
type APIAuthentication struct {
	Key, Email string
}

type zonesResult struct {
	Success    bool        `json:"success"`
	Errors     interface{} `json:"errors"`
	Messages   interface{} `json:"messages"`
	Zones      []Zone      `json:"result"`
	ResultInfo resultInfo  `json:"result_info"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

type listResult struct {
	Success           bool               `json:"success"`
	Errors            interface{}        `json:"errors"`
	Messages          interface{}        `json:"messages"`
	SSLConfigurations []SSLConfiguration `json:"result,omitempty"`
}

type sslConfigResult struct {
	Success          bool             `json:"success"`
	Errors           interface{}      `json:"errors"`
	Messages         interface{}      `json:"messages"`
	SSLConfiguration SSLConfiguration `json:"result,omitempty"`
}

type SSLConfiguration struct {
	ID          string    `json:"id,omitempty"`
	Hosts       []string  `json:"hosts,omitempty"`
	ZoneID      string    `json:"zone_id,omitempty"`
	ExpiresOn   time.Time `json:"expires_on,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	PrivateKey  string    `json:"private_key,omitempty"`
}

func (sslConfig *SSLConfiguration) CertificateEqual(rawCertificate []byte) (bool, error) {
	block, _ := pem.Decode(rawCertificate)
	if block == nil {
		return false, fmt.Errorf("Decoding certificate failed: %v", rawCertificate)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	return sslConfig.ExpiresOn.Equal(certificate.NotAfter), nil
}
