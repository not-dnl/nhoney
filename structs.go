package main

type Config struct {
	ShodanEnabled bool       `json:"shodanEnabled"`
	NmapEnabled   bool       `json:"nmapEnabled"`
	IPs           []string   `json:"IPs"`
	IPRange       []string   `json:"IPRange"`
	Ports         []int      `json:"ports"`
	PingCheck     bool       `json:"pingCheck"`
	Timeout       int        `json:"timeout"`
	Honeypots     []Honeypot `json:"honeypots"`
}

type Honeypot struct {
	Name       string      `json:"name"`
	Protocol   string      `json:"protocol"`
	Ports      []int       `json:"ports"`
	Operations []Operation `json:"operations"`
}

type Operation struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

type Result struct {
	IP               string
	Port             int
	HoneypotVariant  string
	IsHoneypot       bool
	IsHoneypotShodan bool
	OpenPorts        []int
	Vulns            []string
	Cpes             []string
}
