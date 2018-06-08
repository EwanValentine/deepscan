package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Result is a scan result
type Result struct {
	Addr          string
	Hosts         []string
	ReverseLookup []string
	Cname         string
	PortScan      []PortScanResult
}

// PortScanResult is an active/inactive status of a port
type PortScanResult struct {
	Port   uint32
	Active bool
}

// Scanner is the main program
type Scanner struct {
	ipScanResults   chan *Result
	portScanResults chan *Result
	Results         chan *Result
	ips             []string
	quit            chan bool
}

// New scanner constructor
func New() (*Scanner, error) {
	ipScanResults := make(chan *Result, 1)
	portScanResults := make(chan *Result, 1000)
	Results := make(chan *Result, 1)
	quit := make(chan bool)
	ips := []string{}
	return &Scanner{ipScanResults, portScanResults, Results, ips, quit}, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Network allows for a network CIDR range to be set
func (s *Scanner) Network(network string) error {
	ips, err := getHosts(network)
	color.Green(fmt.Sprintf("Found ip addresses in range:%d", len(ips)))
	if err != nil {
		return err
	}
	batchSize := 20
	ipScanResults := make(chan *Result, len(ips)/batchSize)
	s.ipScanResults = ipScanResults
	s.ips = ips
	return nil
}

// getHosts gets all ips within a CIDR block
func getHosts(network string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips[1 : len(ips)-1], nil
}

// getNetworkAddrs fetches all the machines present on the network
func getNetworkAddrs(network string) ([]string, error) {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{}, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return []string{}, err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			ips = append(ips, ip.String())
		}
	}
	return ips, err
}

func (s *Scanner) scan(ip string) {
	// Scan each ip address for an active host
	reverse, err := net.LookupAddr(ip)
	// Skip if not valid host found during lookup
	if err != nil {
		return
	}
	host, err := net.LookupHost(ip)
	cname, err := net.LookupCNAME(ip)
	s.ipScanResults <- &Result{
		Hosts:         host,
		ReverseLookup: reverse,
		Cname:         cname,
		Addr:          ip,
	}
}

// portScan takes a result object, this is the result of the
// ip scan, it also takes a start and an end port number.
// It will then create a wait group, iterate through each
// port number concurrently until it reaches the end port.
// it will store each result on the result object, when it has
// reached the end, it will push the result onto the port
// scan results channel.
func (s *Scanner) portScan(result *Result, start, end uint32) {
	var wg sync.WaitGroup

	// Foreach port
	for i := start; i < end; i++ {
		port := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			// log.Println("Scanning port:", port, "on ip:", result.Addr)

			// Connect with a 1 second timeout
			// @todo - make this configurable?
			connection, err := net.DialTimeout(
				"tcp", result.Addr+":"+fmt.Sprintf("%d", port),
				time.Duration(1*time.Second)*time.Second,
			)

			// Port inactive
			if err != nil {
				return
			}
			connection.Close()

			// log.Println("Found a port:", port)

			// Add the found port to the list of port results
			result.PortScan = append(result.PortScan, PortScanResult{
				Port:   port,
				Active: true,
			})
		}()
	}

	// Wait until every port has been scanned
	wg.Wait()

	// Then return result back to final channel
	s.portScanResults <- result
}

// Start the scan
func (s *Scanner) Start(start, end uint32) {

	// Start a go routine to scan through each
	// ip concurrently
	go func() {
		for _, ip := range s.ips {
			s.scan(ip)
		}
		close(s.ipScanResults)
	}()

	// Start a go routine to listen for ip scan results
	// it will then perform on a port scan on that ip
	// address concurrently.
	go func() {
		for result := range s.ipScanResults {
			go s.portScan(result, start, end)
		}
		// @todo - I feel like this will cut-off
		// too soon, but we need to close this
		// channel in order to complete the next routine
		close(s.portScanResults)
	}()

	// Here we sit and listen for port scan result
	// and we pick out any that have open ports, and
	// ignore the rest.
	go func() {
		for result := range s.portScanResults {
			if len(result.PortScan) > 0 {
				s.Results <- result
			}
		}
		s.Stop()
	}()
}

// Single scans a single ip
func (s *Scanner) Single(ip string, start, end uint32) {

	// Scan ip address
	go func() {
		s.scan(ip)
		close(s.ipScanResults)
	}()

	// Scan ports
	go func() {
		result := <-s.ipScanResults
		s.portScan(result, start, end)
	}()

	go func() {
		result := <-s.portScanResults
		if len(result.PortScan) > 0 {
			s.Results <- result
		}
		s.quit <- true
	}()
}

// Listen for results
func (s *Scanner) Listen() <-chan *Result {
	return s.Results
}

// Close closes any channels created
func (s *Scanner) Close() {
	close(s.Results)
}

// Stop ends the listener
func (s *Scanner) Stop() {
	s.quit <- true
}

// OnStop blocks until complete
func (s *Scanner) OnStop() <-chan bool {
	return s.quit
}
