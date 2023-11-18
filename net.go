package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"
)

func ping(ip string) bool {
	// 500ms hardcoded -W
	cmd := exec.Command("ping", "-c", "1", "-W", "0.5", ip)
	err := cmd.Run()

	return err == nil
}

func connect(ip string, port int, protocol string, config Config) net.Conn {
	if protocol != "tcp" {
		log.Printf("Invalid protocol: %s", protocol)
		return nil
	}

	conn, err := net.DialTimeout(protocol, fmt.Sprintf("%s:%d", ip, port),
		time.Duration(config.Timeout)*time.Millisecond)
	if err != nil {
		return nil
	}

	err = conn.SetDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Millisecond))
	if err != nil {
		log.Printf("Failed to set Read-Write-Deadline: %s", err)

		err := conn.Close()
		if err != nil {
			log.Printf("Failed to Close: %s", err)
			return nil
		}
		return nil
	}

	return conn
}

func sendRequest(conn net.Conn, operation Operation, config Config) error {
	err := conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Millisecond))
	if err != nil {
		log.Printf("Failed to set Read-Deadline: %s", err)
		return err
	}

	// TODO: If we ever have the need to use non string based requests we will implement them here,
	// TODO: along with adding another field to the config json
	request := []byte(operation.Input + "\n")

	_, err = conn.Write(request)
	if err != nil {
		log.Printf("Failed to Write the request: %s", err)
		return err
	}

	log.Printf("Request sent: %s", operation.Input)

	return nil
}

func readResponse(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)

	response, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to Read the response: %s", err)
		return "", err
	}

	log.Printf("Response received: %s", response)

	return response, nil
}
