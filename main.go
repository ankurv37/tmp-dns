package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/miekg/dns"
)

// DNSOverTCP performs a DNS query over TCP
func DNSOverTCP(domain, dnsServer string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	// Create a TCP connection
	conn, err := net.Dial("tcp", dnsServer+":53")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	// Pack the message
	msgBytes, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	// Prefix with two-byte length
	var buf bytes.Buffer
	length := uint16(len(msgBytes))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length & 0xFF))
	buf.Write(msgBytes)

	// Send the message
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to send DNS query: %v", err)
	}

	// Read the response length
	lengthBytes := make([]byte, 2)
	_, err = conn.Read(lengthBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read response length: %v", err)
	}
	respLength := int(lengthBytes[0])<<8 | int(lengthBytes[1])

	// Read the DNS response
	respBytes := make([]byte, respLength)
	_, err = conn.Read(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %v", err)
	}

	// Unpack the response
	resp := new(dns.Msg)
	err = resp.Unpack(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %v", err)
	}

	return resp, nil
}

// DNSOverHTTPS performs a DNS query over HTTPS (DoH)
func DNSOverHTTPS(domain, dohURL string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	msgBytes, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %v", err)
	}

	// Encode the DNS query in base64 URL without padding
	encoded := base64.RawURLEncoding.EncodeToString(msgBytes)

	// Construct the DoH GET request URL
	fullURL := fmt.Sprintf("%s?dns=%s", dohURL, encoded)

	// Create HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// Set appropriate headers
	req.Header.Set("Accept", "application/dns-message")

	// Perform the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("DoH server returned non-OK status: %s, body: %s", resp.Status, string(body))
	}

	// Read the DNS response
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %v", err)
	}

	// Unpack the DNS response
	respMsg := new(dns.Msg)
	err = respMsg.Unpack(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %v", err)
	}

	return respMsg, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <domain> [tcp|http]\n", os.Args[0])
		os.Exit(1)
	}

	domain := os.Args[1]
	method := "tcp" // default method
	if len(os.Args) >= 3 {
		method = os.Args[2]
	}

	var response *dns.Msg
	var err error

	switch method {
	case "tcp":
		// Example DNS server: 8.8.8.8 (Google DNS)
		response, err = DNSOverTCP(domain, "8.8.8.8", dns.TypeA)
	case "http":
		// Example DoH endpoint: Cloudflare
		response, err = DNSOverHTTPS(domain, "https://cloudflare-dns.com/dns-query", dns.TypeA)
	default:
		log.Fatalf("Unknown method: %s. Use 'tcp' or 'http'.", method)
	}

	if err != nil {
		log.Fatalf("DNS query failed: %v", err)
	}

	// Print the DNS response
	fmt.Printf("DNS Response for %s:\n", domain)
	for _, ans := range response.Answer {
		fmt.Println(ans)
	}
}
