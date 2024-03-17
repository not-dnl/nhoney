package main

import (
	"github.com/charmbracelet/log"
	"math/rand"
	"net"
	"strings"
	"time"
)

func arrayContainsInt(arr []int, target int) bool {
	for _, value := range arr {
		if value == target {
			return true
		}
	}
	return false
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parseIPs(input string) []string {
	var IPs []string

	splitted := strings.Split(input, ",")
	for _, split := range splitted {
		if strings.Contains(split, "/") {
			ip, ipNet, err := net.ParseCIDR(split)
			if err != nil {
				return nil
			}
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
				IPs = append(IPs, ip.String())
			}
		} else {
			parts := strings.Split(split, "-")

			startIP := net.ParseIP(parts[0])
			endIP := net.ParseIP(parts[1])

			if startIP == nil || endIP == nil {
				log.Errorf("Invalid IP range")
				return nil
			}

			for ip := startIP; !ip.Equal(endIP); inc(ip) {
				IPs = append(IPs, ip.String())
			}

			IPs = append(IPs, endIP.String())
		}
	}

	return IPs
}

func arrayContainsString(array []string, str string) bool {
	for _, s := range array {
		if s == str {
			return true
		}
	}
	return false
}

func concatenateIntArrayUnique(array1 []int, array2 []int) []int {
	concatenated := append(array1, array2...)

	unique := make(map[int]bool)
	var result []int

	for _, item := range concatenated {
		if _, found := unique[item]; !found {
			unique[item] = true
			result = append(result, item)
		}
	}

	return result
}

func shuffleStringArray(arr []string) []string {
	rand.Seed(time.Now().UnixNano())

	for i := len(arr) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		arr[i], arr[j] = arr[j], arr[i]
	}
	return arr
}
