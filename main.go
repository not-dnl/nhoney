package main

import (
	"encoding/json"
	"log"
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
			log.Printf("Couldn't connect. IP: %s, Port: %d", ip, port)
			continue
		}

		log.Printf("Checking for: %s. IP: %s, Port: %d", honeypot.Name, ip, port)

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
				log.Printf("Operation match! IP: %s, Port: %d, Honey: %s, Response: %s",
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
		log.Printf("Error initDB")
		return
	}

	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Printf("Couldn't Read config.json: %s", err)
		return
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Printf("Error Unmarshaling config.json: %s", err)
		return
	}

	ips := config.IPs
	ports := config.Ports

	ips = removeExistingEntriesFromArray(db, ips)

	var results []Result

	for _, ip := range ips {
		for _, port := range ports {
			results = append(results, isHoneypot(ip, port, config)...)
		}
	}

	err = insertResult(db, results)
	if err != nil {
		log.Print(err)
	}
}
