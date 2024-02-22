package main

import (
	"context"
	"github.com/Ullaakut/nmap/v3"
	"github.com/charmbracelet/log"
	"time"
)

func nmapScan(ip string) []int {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	s, err := nmap.NewScanner(
		ctx,
		nmap.WithFastMode(),
		nmap.WithTargets(ip),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	// Executes asynchronously, allowing results to be streamed in real time.
	done := make(chan error)
	result, warnings, err := s.Async(done).Run()
	if err != nil {
		log.Fatal(err)
	}

	// Blocks main until the scan has completed.
	if err := <-done; err != nil {
		if len(*warnings) > 0 {
			log.Warnf("nmap run finished with warnings: %s", *warnings)
		}
		log.Fatal(err)
	}

	var openPorts []int

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			if port.State.State == "open" || port.State.State == "filtered" {
				openPorts = append(openPorts, int(port.ID))
			}
		}
	}

	return openPorts
}
