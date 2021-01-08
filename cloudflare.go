package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Cloudflare is the object to perform Cloudflare api calls with
type Cloudflare struct {
	restClient     restClient
	authentication APIAuthentication
	baseURL        string
}

// New returns an initialized APIClient
func NewCloudflare(authentication APIAuthentication) *Cloudflare {

	return &Cloudflare{
		restClient:     new(realRESTClient),
		authentication: authentication,
		baseURL:        "https://api.cloudflare.com/client/v4",
	}
}

func (cf *Cloudflare) getZonesByName(zoneName string) (r zonesResult, err error) {

	// create api url
	findZoneURI := fmt.Sprintf("%v/zones/?name=%v", cf.baseURL, zoneName)

	// fetch result from cloudflare api
	body, err := cf.restClient.Get(findZoneURI, cf.authentication)
	if err != nil {
		return r, err
	}

	json.NewDecoder(bytes.NewReader(body)).Decode(&r)

	if !r.Success {
		err = fmt.Errorf("Listing cloudflare zones failed | %v | %v", r.Errors, r.Messages)
		return
	}

	return
}

// GetZoneByDNSName returns the Cloudflare zone by looking it up with a dnsName, possibly including subdomains; also works for TLDs like .co.uk.
func (cf *Cloudflare) GetZoneByDNSName(dnsName string) (r Zone, err error) {

	// split dnsName
	dnsNameParts := strings.Split(dnsName, ".")

	// verify dnsName has enough parts
	if len(dnsNameParts) < 2 {
		err = errors.New("cloudflare: dnsName has too few parts, should at least have a tld and domain name")
		return
	}

	// start taking parts from the end of dnsName and see if cloudflare has a zone for them
	numberOfZoneItems := 2
	zoneNameParts, err := getLastItemsFromSlice(dnsNameParts, numberOfZoneItems)
	if err != nil {
		return r, err
	}

	zoneName := strings.Join(zoneNameParts, ".")
	zonesResult, err := cf.getZonesByName(zoneName)
	if err != nil {
		return r, err
	}

	// if matching zones results fit in a single page get the fully matching zone from the results, otherwise narrow down the search
	if (zonesResult.ResultInfo.Count > 0) && (zonesResult.ResultInfo.Count <= zonesResult.ResultInfo.PerPage) {
		r, err = getMatchingZoneFromZones(zonesResult.Zones, zoneName)
		return
	}

	// if too many zones or none exist for last 2 parts of the dns name, we have to narrow down the search by specifying a more detailed name
	for ((zonesResult.ResultInfo.TotalCount == 0) || (zonesResult.ResultInfo.TotalCount > zonesResult.ResultInfo.PerPage)) && (numberOfZoneItems < len(dnsNameParts)) {
		numberOfZoneItems++
		zoneNameParts, err = getLastItemsFromSlice(dnsNameParts, numberOfZoneItems)
		if err != nil {
			return
		}

		zoneName = strings.Join(zoneNameParts, ".")
		zonesResult, err = cf.getZonesByName(zoneName)
		if err != nil {
			return
		}

		if (zonesResult.ResultInfo.Count > 0) && (zonesResult.ResultInfo.Count <= zonesResult.ResultInfo.PerPage) {
			r, err = getMatchingZoneFromZones(zonesResult.Zones, zoneName)
			return
		}
	}

	err = errors.New("cloudflare: no matching zone has been found")
	return
}

func (cf *Cloudflare) createSSLConfigurationByZone(zone Zone, certificate, privateKey string) (r createResult, err error) {
	// create ssl config at cloudflare api
	newSSLConfiguration := SSLConfiguration{Certificate: certificate, PrivateKey: privateKey}

	createSSLConfigurationURI := fmt.Sprintf("%v/zones/%v/custom_certificates", cf.baseURL, zone.ID)

	body, err := cf.restClient.Post(createSSLConfigurationURI, newSSLConfiguration, cf.authentication)
	if err != nil {
		return r, err
	}

	json.NewDecoder(bytes.NewReader(body)).Decode(&r)

	if !r.Success {
		err = fmt.Errorf("Creating cloudflare ssl config failed | %v | %v", r.Errors, r.Messages)
		return
	}

	return

}

func (cf *Cloudflare) CreateSSLConfiguration(dnsRecordName, certificate, privateKey string) (r SSLConfiguration, err error) {

	// get zone
	zone, err := cf.GetZoneByDNSName(dnsRecordName)
	if err != nil {
		return r, err
	}

	// create record at cloudflare api
	var cloudflareSSLConfigCreateResult createResult
	cloudflareSSLConfigCreateResult, err = cf.createSSLConfigurationByZone(zone, certificate, privateKey)
	if err != nil {
		return
	}

	r = cloudflareSSLConfigCreateResult.SSLConfiguration

	return

}

func getLastItemsFromSlice(source []string, numberOfItems int) (r []string, err error) {

	if len(source) == 0 {
		err = errors.New("cloudflare: argument source is nil")
		return
	}
	if numberOfItems > len(source) {
		err = fmt.Errorf("cloudflare: argument numberOfItems (%v) is larger than number of items in argument source (%v)", numberOfItems, len(source))
		return
	}

	r = make([]string, numberOfItems)
	sourceLength := len(source)
	r = source[sourceLength-numberOfItems:]
	return
}

func getMatchingZoneFromZones(zones []Zone, zoneName string) (r Zone, err error) {

	if len(zones) == 0 {
		err = errors.New("cloudflare: zones cannot be empty")
		return
	}

	for _, zone := range zones {
		if zone.Name == zoneName {
			r = zone
			return
		}
	}

	err = errors.New("cloudflare: no zone matches name")
	return
}
