package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type fakeRESTClient struct {
	mock.Mock
}

func (r *fakeRESTClient) Get(cloudflareAPIURL string, authentication APIAuthentication) (body []byte, err error) {
	args := r.Called(cloudflareAPIURL, authentication)
	return args.Get(0).([]byte), args.Error(1)
}

func (r *fakeRESTClient) Post(cloudflareAPIURL string, params interface{}, authentication APIAuthentication) (body []byte, err error) {
	args := r.Called(cloudflareAPIURL, params, authentication)
	return args.Get(0).([]byte), args.Error(1)
}

func (r *fakeRESTClient) Patch(cloudflareAPIURL string, params interface{}, authentication APIAuthentication) (body []byte, err error) {
	args := r.Called(cloudflareAPIURL, params, authentication)
	return args.Get(0).([]byte), args.Error(1)
}

func TestGetZoneByDNSName(t *testing.T) {

	t.Run("ReturnsErrorWhenDnsNameIsEmptyString", func(t *testing.T) {

		dnsName := ""
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		_, err := apiClient.GetZoneByDNSName(dnsName)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsErrorWhenDnsNameIsOnlyATLD", func(t *testing.T) {

		dnsName := "com"
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		_, err := apiClient.GetZoneByDNSName(dnsName)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsZoneWhenDnsNameEqualsAnExistingZone", func(t *testing.T) {

		dnsName := "server.com"
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/?name=server.com", authentication).Return([]byte(`
		{
			"success": true,
			"errors": [],
			"messages": [],
			"result": [
				{
					"id": "023e105f4ecef8ad9ca31a8372d0c353",
					"name": "server.com",
					"development_mode": 7200,
					"original_name_servers": [
						"ns1.originaldnshost.com",
						"ns2.originaldnshost.com"
					],
					"original_registrar": "GoDaddy",
					"original_dnshost": "NameCheap",
					"created_on": "2014-01-01T05:20:00.12345Z",
					"modified_on": "2014-01-01T05:20:00.12345Z",
					"name_servers": [
						"tony.ns.cloudflare.com",
						"woz.ns.cloudflare.com"
					],
					"owner": {
						"id": "7c5dae5552338874e5053f2534d2767a",
						"email": "user@example.com",
						"owner_type": "user"
					},
					"permissions": [
						"#zone:read",
						"#zone:edit"
					],
					"plan": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"plan_pending": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"status": "active",
					"paused": false,
					"type": "full",
					"checked_on": "2014-01-01T05:20:00.12345Z"
				}
			],
			"result_info": {
				"page": 1,
				"per_page": 20,
				"count": 1,
				"total_count": 1
			}
		}
		`), nil)

		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		zone, err := apiClient.GetZoneByDNSName(dnsName)

		assert.Nil(t, err)
		assert.Equal(t, "023e105f4ecef8ad9ca31a8372d0c353", zone.ID)
		assert.Equal(t, "server.com", zone.Name)
	})

}

func TestGetZonesByName(t *testing.T) {

	t.Run("ReturnsEmptyArrayIfNoZoneMatchesName", func(t *testing.T) {

		zoneName := "server.com"
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/?name=server.com", authentication).Return([]byte(`
			{
				"success": true,
				"errors": [],
				"messages": [],
				"result": [
				],
				"result_info": {
					"page": 1,
					"per_page": 20,
					"count": 0,
					"total_count": 0
				}
			}
		`), nil)

		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		zonesResult, err := apiClient.getZonesByName(zoneName)

		assert.Nil(t, err)
		assert.Equal(t, 0, len(zonesResult.Zones))
	})

	t.Run("ReturnsSingleZoneIfZoneMatchesName", func(t *testing.T) {

		zoneName := "server.com"
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/?name=server.com", authentication).Return([]byte(`
		{
			"success": true,
			"errors": [],
			"messages": [],
			"result": [
				{
					"id": "023e105f4ecef8ad9ca31a8372d0c353",
					"name": "server.com",
					"development_mode": 7200,
					"original_name_servers": [
						"ns1.originaldnshost.com",
						"ns2.originaldnshost.com"
					],
					"original_registrar": "GoDaddy",
					"original_dnshost": "NameCheap",
					"created_on": "2014-01-01T05:20:00.12345Z",
					"modified_on": "2014-01-01T05:20:00.12345Z",
					"name_servers": [
						"tony.ns.cloudflare.com",
						"woz.ns.cloudflare.com"
					],
					"owner": {
						"id": "7c5dae5552338874e5053f2534d2767a",
						"email": "user@example.com",
						"owner_type": "user"
					},
					"permissions": [
						"#zone:read",
						"#zone:edit"
					],
					"plan": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"plan_pending": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"status": "active",
					"paused": false,
					"type": "full",
					"checked_on": "2014-01-01T05:20:00.12345Z"
				}
			],
			"result_info": {
				"page": 1,
				"per_page": 20,
				"count": 1,
				"total_count": 1
			}
		}
		`), nil)

		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		zonesResult, err := apiClient.getZonesByName(zoneName)

		assert.Nil(t, err)
		assert.Equal(t, 1, len(zonesResult.Zones))
		assert.Equal(t, "023e105f4ecef8ad9ca31a8372d0c353", zonesResult.Zones[0].ID)
		assert.Equal(t, "server.com", zonesResult.Zones[0].Name)
	})

	t.Run("ReturnsMultipleZonesIfMoreThanOneZoneMatchesName", func(t *testing.T) {

		zoneName := "co.uk"
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/?name=co.uk", authentication).Return([]byte(`
		{
			"success": true,
			"errors": [],
			"messages": [],
			"result": [
				{
					"id": "023e105f48ad9ca31a8372d0c353ecef",
					"name": "domain.co.uk",
					"development_mode": 7200,
					"original_name_servers": [
						"ns1.originaldnshost.com",
						"ns2.originaldnshost.com"
					],
					"original_registrar": "GoDaddy",
					"original_dnshost": "NameCheap",
					"created_on": "2014-01-01T05:20:00.12345Z",
					"modified_on": "2014-01-01T05:20:00.12345Z",
					"name_servers": [
						"tony.ns.cloudflare.com",
						"woz.ns.cloudflare.com"
					],
					"owner": {
						"id": "7c5dae5552338874e5053f2534d2767a",
						"email": "user@example.com",
						"owner_type": "user"
					},
					"permissions": [
						"#zone:read",
						"#zone:edit"
					],
					"plan": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"plan_pending": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"status": "active",
					"paused": false,
					"type": "full",
					"checked_on": "2014-01-01T05:20:00.12345Z"
				},
				{
					"id": "023e105f4ecef8ad9ca31a8372d0c353",
					"name": "server.co.uk",
					"development_mode": 7200,
					"original_name_servers": [
						"ns1.originaldnshost.com",
						"ns2.originaldnshost.com"
					],
					"original_registrar": "GoDaddy",
					"original_dnshost": "NameCheap",
					"created_on": "2014-01-01T05:20:00.12345Z",
					"modified_on": "2014-01-01T05:20:00.12345Z",
					"name_servers": [
						"tony.ns.cloudflare.com",
						"woz.ns.cloudflare.com"
					],
					"owner": {
						"id": "7c5dae5552338874e5053f2534d2767a",
						"email": "user@example.com",
						"owner_type": "user"
					},
					"permissions": [
						"#zone:read",
						"#zone:edit"
					],
					"plan": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"plan_pending": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"status": "active",
					"paused": false,
					"type": "full",
					"checked_on": "2014-01-01T05:20:00.12345Z"
				}
			],
			"result_info": {
				"page": 1,
				"per_page": 20,
				"count": 1,
				"total_count": 1
			}
		}
		`), nil)

		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		zonesResult, err := apiClient.getZonesByName(zoneName)

		assert.Nil(t, err)
		assert.Equal(t, 2, len(zonesResult.Zones))
		assert.Equal(t, "023e105f48ad9ca31a8372d0c353ecef", zonesResult.Zones[0].ID)
		assert.Equal(t, "domain.co.uk", zonesResult.Zones[0].Name)
		assert.Equal(t, "023e105f4ecef8ad9ca31a8372d0c353", zonesResult.Zones[1].ID)
		assert.Equal(t, "server.co.uk", zonesResult.Zones[1].Name)
	})
}

func TestUpsertSSLConfiguration(t *testing.T) {

	t.Run("ReturnsErrorIfZoneDoesNotExist", func(t *testing.T) {

		dnsRecordName := "example.com"
		certificate := []byte("")
		privateKey := []byte("")
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/?name=example.com", authentication).Return([]byte(`
			{
				"success": true,
				"errors": [],
				"messages": [],
				"result": [
				],
				"result_info": {
					"page": 1,
					"per_page": 20,
					"count": 0,
					"total_count": 0
				}
			}
		`), nil)

		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		_, err := apiClient.UpsertSSLConfigurationByDNSName(dnsRecordName, certificate, privateKey)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsSSLConfigIfCreated", func(t *testing.T) {

		dnsRecordName := "example.com"
		certificate := []byte("")
		privateKey := []byte("")
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/?name=example.com", authentication).Return([]byte(`
		{
			"success": true,
			"errors": [],
			"messages": [],
			"result": [
				{
					"id": "023e105f4ecef8ad9ca31a8372d0c353",
					"name": "example.com",
					"development_mode": 7200,
					"original_name_servers": [
						"ns1.originaldnshost.com",
						"ns2.originaldnshost.com"
					],
					"original_registrar": "GoDaddy",
					"original_dnshost": "NameCheap",
					"created_on": "2014-01-01T05:20:00.12345Z",
					"modified_on": "2014-01-01T05:20:00.12345Z",
					"name_servers": [
						"tony.ns.cloudflare.com",
						"woz.ns.cloudflare.com"
					],
					"owner": {
						"id": "7c5dae5552338874e5053f2534d2767a",
						"email": "user@example.com",
						"owner_type": "user"
					},
					"permissions": [
						"#zone:read",
						"#zone:edit"
					],
					"plan": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"plan_pending": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"status": "active",
					"paused": false,
					"type": "full",
					"checked_on": "2014-01-01T05:20:00.12345Z"
				}
			],
			"result_info": {
				"page": 1,
				"per_page": 20,
				"count": 1,
				"total_count": 1
			}
		}
		`), nil)

		newSSLConfiguration := SSLConfiguration{Certificate: string(certificate), PrivateKey: string(privateKey)}

		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353/custom_certificates", authentication).Return([]byte(`
			{
				"success": true,
				"errors": [],
				"messages": [],
				"result": []
			}
                `), nil)

		fakeRESTClient.On("Post", "https://api.cloudflare.com/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353/custom_certificates", newSSLConfiguration, authentication).Return([]byte(`
			{
				"success": true,
				"errors": [],
				"messages": [],
				"result": {
					"id": "372e67954025e0ba6aaa6d586b9e0b59",
                                        "hosts": ["example.com"],
					"zone_id": "023e105f4ecef8ad9ca31a8372d0c353"
				}
			}
		`), nil)

		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		sslConfig, err := apiClient.UpsertSSLConfigurationByDNSName(dnsRecordName, certificate, privateKey)

		assert.Nil(t, err)
		assert.Equal(t, "372e67954025e0ba6aaa6d586b9e0b59", sslConfig.ID)
		assert.Equal(t, []string{"example.com"}, sslConfig.Hosts)
		assert.Equal(t, "023e105f4ecef8ad9ca31a8372d0c353", sslConfig.ZoneID)
	})

	t.Run("ReturnsSSLConfigIfUpdated", func(t *testing.T) {

		dnsRecordName := "example.com"
		certificate := []byte(`-----BEGIN CERTIFICATE-----
		MIIDpzCCAo+gAwIBAgIUV9Za3+vEd4NAPcCHCcQ4xSay2AwwDQYJKoZIhvcNAQEL
		BQAwYzELMAkGA1UEBhMCTkwxFjAUBgNVBAgMDU5vb3JkLUhvbGxhbmQxEjAQBgNV
		BAcMCUFtc3RlcmRhbTESMBAGA1UECgwJRXN0YWZldHRlMRQwEgYDVQQDDAtleGFt
		cGxlLmNvbTAeFw0yMTAxMTMxMDIwMzZaFw0yMjAxMTMxMDIwMzZaMGMxCzAJBgNV
		BAYTAk5MMRYwFAYDVQQIDA1Ob29yZC1Ib2xsYW5kMRIwEAYDVQQHDAlBbXN0ZXJk
		YW0xEjAQBgNVBAoMCUVzdGFmZXR0ZTEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEi
		MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC57mKTu1ytoSSDyUm8xmwPklua
		s/1ITsUqdYJc+FDehWsKTOGg1tb6uH2DY4DkwGCbROH1xJ32R9szgCiazVrBuYF1
		l6pm1lURZWnMY2iT16WFu3VxVW3N4mgNclKePNV/UP1lEyb1MGxeOAud5D0MVzal
		U+2v83SEOg1hn1v7v2kA4jJWLY+9UIB51Yqq+pARvJbAH0uct0au7Q7z0RNvzoq/
		pwVy44/IE/gWlhp/ShYKhwfhGM7NM+vCUAUeIVFglcawDNbLPftaewexdoAsWR4U
		462n9fNoCw+7yxOU1+Htc8jODx1TZ6IDsGZgkR8zUH4csUKr1R9lm1UoL5x5AgMB
		AAGjUzBRMB0GA1UdDgQWBBTuWf+0GFS7hW8xgUoO69U8NetiuDAfBgNVHSMEGDAW
		gBTuWf+0GFS7hW8xgUoO69U8NetiuDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
		DQEBCwUAA4IBAQBu4ZccOOQWuBdM0YdY+uzzVXmGE/et4yNlQm03hNQb1IcLdSHP
		4BHmTy9ARjz+v4OSVuA/dVxwqqZGA0bl5IaPhyjqnDk0iGcHRwJmBflMmf+bY7HF
		6Q6+mNRRjKJawNq2lpOU1d1oNCNmIZ9WlphDqU3OQ4TvkyK2vJIK53oXhGREpG8f
		EMqd/bUr6SVVhzhozDV0zUHyO8KlF5faFzft1uu9d6zpmkuuDE+81W14b3fjp4NU
		gfwu4hL84kwdwaQo75OY6iSfvQJwcblefHLNhaw6EnfMA3NHpw9XYlxFui9hrr6z
		AQ3xIhzw9u+jq2YrQTUVUE5KhpIGY5RXSFhs
-----END CERTIFICATE-----`)
		privateKey := []byte("")
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/?name=example.com", authentication).Return([]byte(`
		{
			"success": true,
			"errors": [],
			"messages": [],
			"result": [
				{
					"id": "023e105f4ecef8ad9ca31a8372d0c353",
					"name": "example.com",
					"development_mode": 7200,
					"original_name_servers": [
						"ns1.originaldnshost.com",
						"ns2.originaldnshost.com"
					],
					"original_registrar": "GoDaddy",
					"original_dnshost": "NameCheap",
					"created_on": "2014-01-01T05:20:00.12345Z",
					"modified_on": "2014-01-01T05:20:00.12345Z",
					"name_servers": [
						"tony.ns.cloudflare.com",
						"woz.ns.cloudflare.com"
					],
					"owner": {
						"id": "7c5dae5552338874e5053f2534d2767a",
						"email": "user@example.com",
						"owner_type": "user"
					},
					"permissions": [
						"#zone:read",
						"#zone:edit"
					],
					"plan": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"plan_pending": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"status": "active",
					"paused": false,
					"type": "full",
					"checked_on": "2014-01-01T05:20:00.12345Z"
				}
			],
			"result_info": {
				"page": 1,
				"per_page": 20,
				"count": 1,
				"total_count": 1
			}
		}
		`), nil)

		newSSLConfiguration := SSLConfiguration{Certificate: string(certificate), PrivateKey: string(privateKey)}

		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353/custom_certificates", authentication).Return([]byte(`
			{
				"success": true,
				"errors": [],
				"messages": [],
				"result": [
					{
						"id": "372e67954025e0ba6aaa6d586b9e0b59",
						"hosts": ["example.com"],
						"zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
						"expires_on": "2016-01-01T05:20:00Z"
					}
				]
			}
                `), nil)

		fakeRESTClient.On("Patch", "https://api.cloudflare.com/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353/custom_certificates/372e67954025e0ba6aaa6d586b9e0b59", newSSLConfiguration, authentication).Return([]byte(`
			{
				"success": true,
				"errors": [],
				"messages": [],
				"result": {
					"id": "372e67954025e0ba6aaa6d586b9e0b59",
                                        "hosts": ["example.com"],
					"zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
					"expires_on": "2016-01-01T05:20:00Z"
				}
			}
		`), nil)

		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		sslConfig, err := apiClient.UpsertSSLConfigurationByDNSName(dnsRecordName, certificate, privateKey)

		assert.Nil(t, err)
		assert.Equal(t, "372e67954025e0ba6aaa6d586b9e0b59", sslConfig.ID)
		assert.Equal(t, []string{"example.com"}, sslConfig.Hosts)
		assert.Equal(t, "023e105f4ecef8ad9ca31a8372d0c353", sslConfig.ZoneID)
	})

	t.Run("DoesNotCallPatchIfSSLConfigCertificateIsTheSame", func(t *testing.T) {

		dnsRecordName := "example.com"
		certificate := []byte(`-----BEGIN CERTIFICATE-----
		MIIDpzCCAo+gAwIBAgIUV9Za3+vEd4NAPcCHCcQ4xSay2AwwDQYJKoZIhvcNAQEL
		BQAwYzELMAkGA1UEBhMCTkwxFjAUBgNVBAgMDU5vb3JkLUhvbGxhbmQxEjAQBgNV
		BAcMCUFtc3RlcmRhbTESMBAGA1UECgwJRXN0YWZldHRlMRQwEgYDVQQDDAtleGFt
		cGxlLmNvbTAeFw0yMTAxMTMxMDIwMzZaFw0yMjAxMTMxMDIwMzZaMGMxCzAJBgNV
		BAYTAk5MMRYwFAYDVQQIDA1Ob29yZC1Ib2xsYW5kMRIwEAYDVQQHDAlBbXN0ZXJk
		YW0xEjAQBgNVBAoMCUVzdGFmZXR0ZTEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEi
		MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC57mKTu1ytoSSDyUm8xmwPklua
		s/1ITsUqdYJc+FDehWsKTOGg1tb6uH2DY4DkwGCbROH1xJ32R9szgCiazVrBuYF1
		l6pm1lURZWnMY2iT16WFu3VxVW3N4mgNclKePNV/UP1lEyb1MGxeOAud5D0MVzal
		U+2v83SEOg1hn1v7v2kA4jJWLY+9UIB51Yqq+pARvJbAH0uct0au7Q7z0RNvzoq/
		pwVy44/IE/gWlhp/ShYKhwfhGM7NM+vCUAUeIVFglcawDNbLPftaewexdoAsWR4U
		462n9fNoCw+7yxOU1+Htc8jODx1TZ6IDsGZgkR8zUH4csUKr1R9lm1UoL5x5AgMB
		AAGjUzBRMB0GA1UdDgQWBBTuWf+0GFS7hW8xgUoO69U8NetiuDAfBgNVHSMEGDAW
		gBTuWf+0GFS7hW8xgUoO69U8NetiuDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
		DQEBCwUAA4IBAQBu4ZccOOQWuBdM0YdY+uzzVXmGE/et4yNlQm03hNQb1IcLdSHP
		4BHmTy9ARjz+v4OSVuA/dVxwqqZGA0bl5IaPhyjqnDk0iGcHRwJmBflMmf+bY7HF
		6Q6+mNRRjKJawNq2lpOU1d1oNCNmIZ9WlphDqU3OQ4TvkyK2vJIK53oXhGREpG8f
		EMqd/bUr6SVVhzhozDV0zUHyO8KlF5faFzft1uu9d6zpmkuuDE+81W14b3fjp4NU
		gfwu4hL84kwdwaQo75OY6iSfvQJwcblefHLNhaw6EnfMA3NHpw9XYlxFui9hrr6z
		AQ3xIhzw9u+jq2YrQTUVUE5KhpIGY5RXSFhs
-----END CERTIFICATE-----`)
		privateKey := []byte("")
		authentication := APIAuthentication{Key: "r2kjepva04hijzv18u3e9ntphs79kctdxxj5w", Email: "name@server.com"}

		fakeRESTClient := new(fakeRESTClient)
		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/?name=example.com", authentication).Return([]byte(`
		{
			"success": true,
			"errors": [],
			"messages": [],
			"result": [
				{
					"id": "023e105f4ecef8ad9ca31a8372d0c353",
					"name": "example.com",
					"development_mode": 7200,
					"original_name_servers": [
						"ns1.originaldnshost.com",
						"ns2.originaldnshost.com"
					],
					"original_registrar": "GoDaddy",
					"original_dnshost": "NameCheap",
					"created_on": "2014-01-01T05:20:00.12345Z",
					"modified_on": "2014-01-01T05:20:00.12345Z",
					"name_servers": [
						"tony.ns.cloudflare.com",
						"woz.ns.cloudflare.com"
					],
					"owner": {
						"id": "7c5dae5552338874e5053f2534d2767a",
						"email": "user@example.com",
						"owner_type": "user"
					},
					"permissions": [
						"#zone:read",
						"#zone:edit"
					],
					"plan": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"plan_pending": {
						"id": "e592fd9519420ba7405e1307bff33214",
						"name": "Pro Plan",
						"price": 20,
						"currency": "USD",
						"frequency": "monthly",
						"legacy_id": "pro",
						"is_subscribed": true,
						"can_subscribe": true
					},
					"status": "active",
					"paused": false,
					"type": "full",
					"checked_on": "2014-01-01T05:20:00.12345Z"
				}
			],
			"result_info": {
				"page": 1,
				"per_page": 20,
				"count": 1,
				"total_count": 1
			}
		}
		`), nil)

		fakeRESTClient.On("Get", "https://api.cloudflare.com/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353/custom_certificates", authentication).Return([]byte(`
			{
				"success": true,
				"errors": [],
				"messages": [],
				"result": [
					{
						"id": "372e67954025e0ba6aaa6d586b9e0b59",
						"hosts": ["example.com"],
						"zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
						"expires_on": "2022-01-13T10:20:36Z"
					}
				]
			}
                `), nil)

		apiClient := NewCloudflare(authentication)
		apiClient.restClient = fakeRESTClient

		// act
		sslConfig, err := apiClient.UpsertSSLConfigurationByDNSName(dnsRecordName, certificate, privateKey)

		assert.Nil(t, err)
		assert.Equal(t, "372e67954025e0ba6aaa6d586b9e0b59", sslConfig.ID)
		assert.Equal(t, []string{"example.com"}, sslConfig.Hosts)
		assert.Equal(t, "023e105f4ecef8ad9ca31a8372d0c353", sslConfig.ZoneID)
	})

}
