package main

import (
	"encoding/json"
	"github.com/charmbracelet/log"
	"os"
	"strings"
)

func isHoneypot(ip string, port int, config Config) []Result {
	var results []Result

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

		for _, operation := range honeypot.Operations {
			err := sendRequest(conn, operation, config)
			if err != nil {
				break
			}

			response, err := readResponse(conn)
			if err != nil {
				break
			}

			if strings.Contains(response, operation.Output) {
				log.Infof("Operation match! IP: %s, Port: %d, Honey: %s, Response: %s",
					ip, port, honeypot.Name, response)

				results = append(results, Result{
					IP:               ip,
					Port:             port,
					HoneypotVariant:  honeypot.Name,
					IsHoneypot:       true,
					IsHoneypotShodan: false,
					OpenPorts:        nil,
					Vulns:            nil,
					Cpes:             nil,
				})
			}
		}
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

	ips = removeExistingEntriesFromArray(db, ips)

	log.Infof("Started scan with %d IPs and %d Ports!", len(ips), len(ports))

	var results []Result

	for _, ip := range ips {
		for _, port := range ports {
			results = append(results, isHoneypot(ip, port, config)...)
		}
	}

	err = insertResult(db, results)
	if err != nil {
		log.Error(err)
	}
}
