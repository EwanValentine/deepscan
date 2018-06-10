package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/EwanValentine/deepscan/pkg/network"
	"github.com/fatih/color"
)

// Result is a scan result
type Result struct {
	Addr          string
	Hosts         []string
	ReverseLookup []string
	Cname         string
	PortScan      *PortScanResult
}

// PortScanResult is an active/inactive status of a port
type PortScanResult struct {
	Port   uint32
	Active bool
}

// Scanner is the main program
type Scanner struct {
	Results chan *Result
	ips     []string
	quit    chan bool

	// Stats
	start        time.Time
	end          time.Time
	portsScanned uint32
}

// New scanner constructor
func New() (*Scanner, error) {
	results := make(chan *Result, 1)
	quit := make(chan bool)
	ips := []string{}
	return &Scanner{results, ips, quit, time.Now(), time.Now(), 0}, nil
}

// Network allows for a network CIDR range to be set
func (s *Scanner) Network(cidr string) error {
	ips, err := network.GetHosts(cidr)
	color.Green(fmt.Sprintf("Found ip addresses in range:%d", len(ips)))
	if err != nil {
		return err
	}
	batchSize := 20
	results := make(chan *Result, len(ips)/batchSize)
	s.Results = results
	s.ips = ips
	return nil
}

func (s *Scanner) scan(ip string) *Result {
	// Scan each ip address for an active host
	reverse, err := net.LookupAddr(ip)

	// Skip if not valid host found during lookup
	if err != nil {
		return nil
	}
	host, err := net.LookupHost(ip)
	cname, err := net.LookupCNAME(ip)
	return &Result{
		Hosts:         host,
		ReverseLookup: reverse,
		Cname:         cname,
		Addr:          ip,
	}
}

// output takes a result object, this is the result of the
// ip scan, it also takes a start and an end port number.
// It will then create a wait group, iterate through each
// port number concurrently until it reaches the end port.
// it will store each result on the result object, when it has
// reached the end, it will push the result onto the port
// scan results channel.
func (s *Scanner) scanPort(outcome chan *Result, result *Result, port uint32, wg *sync.WaitGroup) {
	defer wg.Done()
	s.portsScanned++
	// Connect with a 5 second timeout
	// @todo - make this configurable?
	connection, err := net.DialTimeout(
		"tcp", result.Addr+":"+fmt.Sprintf("%d", port),
		time.Duration(5*time.Second),
	)

	// Port inactive
	if err != nil {
		return
	}
	connection.Close()

	result.PortScan = &PortScanResult{
		Port:   port,
		Active: true,
	}
	outcome <- result
}

func (s *Scanner) scanAsync(pipeline []string) <-chan *Result {
	out := make(chan *Result, len(s.ips))
	go func() {
		for _, ip := range pipeline {
			res := s.scan(ip)
			if res != nil {
				out <- res
			}
		}
		close(out)
	}()
	return out
}

func (s *Scanner) scanSingleAsync(ip string) <-chan *Result {
	out := make(chan *Result, 1)
	go func() {
		res := s.scan(ip)
		if res != nil {
			out <- res
		}
		close(out)
	}()
	return out
}

func (s *Scanner) filterResults(results <-chan *Result) {
	go func() {
		for result := range results {
			if result.PortScan != nil {
				s.Results <- result
			}
		}
		s.Stop()
		s.end = time.Now()
	}()
}

func (s *Scanner) portScanAsync(output chan *Result, input <-chan *Result, start, end uint32) chan<- *Result {
	go func() {
		// Create a wait group here so's we can scan each port
		// concurrently without prematurely moving on to the next
		// ip address and closing the output channel prematurely.
		var wg sync.WaitGroup
		// Scan through each ip address
		for result := range input {
			for i := start; i <= end; i++ {
				wg.Add(1)
				go s.scanPort(output, result, i, &wg)
			}
		}
		wg.Wait()
		close(output)
	}()
	return output
}

// Start the scan
func (s *Scanner) Start(start, end uint32) {
	results := s.scanAsync(s.ips)
	portsInRange := end - start
	output := make(chan *Result, portsInRange)
	s.portScanAsync(output, results, start, end)
	s.filterResults(output)
}

// Single scans a single ip
func (s *Scanner) Single(ip string, start, end uint32) {
	results := s.scanSingleAsync(ip)
	portsInRange := end - start
	output := make(chan *Result, portsInRange)
	s.portScanAsync(output, results, start, end)
	s.filterResults(output)
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

// Stats returns
func (s *Scanner) Stats() string {
	duration := s.end.Sub(s.start).Seconds()
	return fmt.Sprintf(
		"Scanned %d ips and %d ports in %f seconds",
		len(s.ips),
		s.portsScanned,
		duration,
	)
}
