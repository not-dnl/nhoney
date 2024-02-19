package main

import (
	"encoding/csv"
	"fmt"
	"github.com/charmbracelet/log"
	"net"
	"os"
	"strconv"
)

type IP2LocationRecord struct {
	IPFrom      string
	IPTo        string
	CountryCode string
	CountryName string
}

func getIPRangesForCountry(countryCode string) []string {
	file, err := os.Open("data/IP2LOCATION-LITE-DB1.CSV")
	if err != nil {
		log.Errorf("Error opening file: %s", err)
		return nil
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Allow variable number of fields per record

	records, err := reader.ReadAll()
	if err != nil {
		log.Errorf("Error reading CSV: %s", err)
		return nil
	}

	var ranges []string

	for _, record := range records {
		ipRecord := parseRecord(record)
		if ipRecord.CountryCode == countryCode {
			ipFrom := convertIP(ipRecord.IPFrom)
			ipTo := convertIP(ipRecord.IPTo)
			if ipFrom == nil || ipTo == nil {
				log.Errorf("Error converting: From: %s, To: %s", ipRecord.IPFrom, ipRecord.IPTo)
				continue
			}

			ranges = append(ranges, fmt.Sprintf("%s-%s", ipFrom, ipTo))
		}
	}

	return ranges
}

func convertIP(input string) net.IP {
	uint32Val, err := strconv.ParseUint(input, 10, 32)
	if err != nil {
		log.Errorf("Error converting IP: %s", err)
		return nil
	}

	ipFrom := uint32(uint32Val)

	ip := make(net.IP, 4)
	ip[0] = byte(ipFrom >> 24)
	ip[1] = byte(ipFrom >> 16)
	ip[2] = byte(ipFrom >> 8)
	ip[3] = byte(ipFrom)

	return ip
}

func parseRecord(record []string) IP2LocationRecord {
	return IP2LocationRecord{
		IPFrom:      record[0],
		IPTo:        record[1],
		CountryCode: record[2],
		CountryName: record[3],
	}
}
