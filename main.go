package main

import (
	"encoding/json"
	"github.com/charmbracelet/log"
	"os"
	"strings"
	"sync"
	"time"
)

func isHoneypot(ip string, port int, config Config) []Result {
	var results []Result
	var shodan *ShodanResponse

	if !config.PingCheck || ping(ip) {
		shodan = shodanRequest(ip, config)

		if config.NmapEnabled {
			nmap := nmapScan(ip)
			shodan.Ports = concatenateIntArrayUnique(shodan.Ports, nmap)
		}

		for _, honeypot := range config.Honeypots {
			if !arrayContainsInt(honeypot.Ports, port) {
				continue
			}

			conn := connect(ip, port, honeypot.Protocol, config)
			if conn == nil {
				log.Debugf("Couldn't connect. IP: %s, Port: %d", ip, port)
				continue
			}

			log.Debugf("Checking for: %s. IP: %s, Port: %d", honeypot.Name, ip, port)

			honeypotMatch := true

			for _, operation := range honeypot.Operations {
				err := sendRequest(conn, operation, config)
				if err != nil {
					honeypotMatch = false
					break
				}

				response, err := readResponse(conn)
				if err != nil {
					honeypotMatch = false
					break
				}

				if strings.Contains(response, operation.Output) {
					honeypotMatch = true
				} else {
					honeypotMatch = false
				}
			}

			if honeypotMatch {
				log.Infof("Honeypot found! IP: %s, Port: %d, Honey: %s",
					ip, port, honeypot.Name)

				results = append(results, Result{
					IP:               ip,
					Port:             port,
					HoneypotVariant:  honeypot.Name,
					IsHoneypot:       true,
					IsHoneypotShodan: arrayContainsString(shodan.Tags, "honeypot"),
					OpenPorts:        shodan.Ports,
					Vulns:            shodan.Vulnerabilities,
					Cpes:             shodan.CPEs,
				})
			} else {
				results = append(results, Result{
					IP:               ip,
					Port:             port,
					HoneypotVariant:  "",
					IsHoneypot:       false,
					IsHoneypotShodan: arrayContainsString(shodan.Tags, "honeypot"),
					OpenPorts:        shodan.Ports,
					Vulns:            shodan.Vulnerabilities,
					Cpes:             shodan.CPEs,
				})
			}
		}
	}

	if len(results) <= 0 {
		var result Result
		if shodan == nil || shodan.IP == "" {
			result = Result{
				IP:               ip,
				Port:             port,
				HoneypotVariant:  "HOST DIDN'T ANSWER ME",
				IsHoneypot:       false,
				IsHoneypotShodan: false,
				OpenPorts:        nil,
				Vulns:            nil,
				Cpes:             nil,
			}
		} else {
			result = Result{
				IP:               ip,
				Port:             port,
				HoneypotVariant:  "HOST DIDN'T ANSWER ME",
				IsHoneypot:       false,
				IsHoneypotShodan: arrayContainsString(shodan.Tags, "honeypot"),
				OpenPorts:        shodan.Ports,
				Vulns:            shodan.Vulnerabilities,
				Cpes:             shodan.CPEs,
			}
		}

		results = append(results, result)
	}

	return results
}

func main() {
	db := initDB()
	if db == nil {
		log.Errorf("Error initDB")
		return
	}

	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Errorf("Couldn't Read config.json: %s", err)
		return
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Errorf("Error Unmarshaling config.json: %s", err)
		return
	}

	ips := config.IPs
	ports := config.Ports

	for _, ipRange := range config.IPRange {
		ips = append(ips, parseIPs(ipRange)...)
	}

	// Alternative way to add whole IP-Ranges of a Country
	// WARNING: Slow!
	/*countryIPRanges := getIPRangesForCountry("RU")
	for _, ipRange := range countryIPRanges {
		ips = append(ips, parseIPs(ipRange)...)
	}*/

	ips = removeExistingEntriesFromArray(db, ips)
	ips = shuffleStringArray(ips) // shuffle them, so we don't flood the same ip-range and potentially get banned that way

	log.Infof("Started scan with %d IPs and %d Ports!", len(ips), len(ports))

	scanStart := time.Now()

	var wg sync.WaitGroup
	resultsCh := make(chan []Result)
	errCh := make(chan error)

	for _, ip := range ips {
		for _, port := range ports {
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				resultsCh <- isHoneypot(ip, port, config)
			}(ip, port)
		}
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var results []Result
	for res := range resultsCh {
		results = append(results, res...)
	}

	scanEnd := time.Since(scanStart)
	log.Infof("Scan took %s ... Inserting to DB\n", scanEnd)

	go func() {
		errCh <- insertResult(db, results)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Error(err)
		}
	}
}
