package main

import (
	"encoding/json"
	"fmt"
	"github.com/charmbracelet/log"
	"io/ioutil"
	"net/http"
)

type ShodanResponse struct {
	CPEs            []string `json:"cpes"`
	Hostnames       []string `json:"hostnames"`
	IP              string   `json:"ip"`
	Ports           []int    `json:"ports"`
	Tags            []string `json:"tags"`
	Vulnerabilities []string `json:"vulns"`
}

func shodanRequest(ip string, config Config) *ShodanResponse {
	// https://internetdb.shodan.io/102.221.36.32

	if !config.ShodanEnabled {
		return &ShodanResponse{}
	}

	url := fmt.Sprintf("https://internetdb.shodan.io/%s", ip)

	client := http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("Error creating request: %s", err)
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error sending request: %s", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("Error Shodan: Unexpected status code: %d", resp.StatusCode)
		return nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response body: %s", err)
		return nil
	}

	var shodanResponse ShodanResponse

	err = json.Unmarshal(body, &shodanResponse)
	if err != nil {
		log.Errorf("Error unmarshalling JSON: %s", err)
		return nil
	}

	return &shodanResponse
}
