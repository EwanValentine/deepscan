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
	quit    chan struct{}
	mu      *sync.Mutex

	// Stats
	start        time.Time
	end          time.Time
	portsScanned uint32
}

// New marks the beginning of operation and retunes a new instance of Scanner.
func New() *Scanner {
	results := make(chan *Result, 1)
	quit := make(chan struct{})
	ips := []string{}
	mutex := &sync.Mutex{}
	return &Scanner{
		Results: results,
		ips:     ips,
		quit:    quit,
		start:   time.Now(),
		mu:      mutex,
	}
}

// Network allows for a network CIDR range to be set
func (s *Scanner) Network(cidr string) error {
	ips, err := network.GetHosts(cidr)
	if err != nil {
		return err
	}
	color.Green(fmt.Sprintf("Found ip addresses in range:%d", len(ips)))
	results := make(chan *Result, len(ips))
	s.Results = results
	s.ips = ips
	return nil
}

// Target sets a single IP
func (s *Scanner) Target(ip string) {
	s.ips = []string{ip}
}

func (s *Scanner) scan(ip string) *Result {
	// Scan each ip address for an active host
	reverse, err := net.LookupAddr(ip)

	// Skip if not valid host found during lookup
	if err != nil {
		return nil
	}

	// @todo - handle these errors correctly
	host, err := net.LookupHost(ip)
	cname, err := net.LookupCNAME(ip)
	return &Result{
		Hosts:         host,
		ReverseLookup: reverse,
		Cname:         cname,
		Addr:          ip,
	}
}

func (s *Scanner) scanPort(result *Result, port uint32) (*Result, error) {
	s.mu.Lock()
	s.portsScanned++
	s.mu.Unlock()

	// Connect with a 1 second timeout
	// @todo - make this configurable?
	connection, err := net.DialTimeout(
		"tcp", result.Addr+":"+fmt.Sprintf("%d", port),
		time.Duration(1*time.Second),
	)

	// Port inactive
	if err != nil {
		return nil, err
	}
	connection.Close()

	result.PortScan = &PortScanResult{
		Port:   port,
		Active: true,
	}
	return result, nil
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

func (s *Scanner) portScanAsync(input <-chan *Result, start, end uint32) {
	// Create a wait group here so's we can scan each port
	// concurrently without prematurely moving on to the next
	// ip address and closing the output channel prematurely.
	var wg sync.WaitGroup
	// Scan through each ip address
	for result := range input {
		for i := start; i <= end; i++ {
			port := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := s.scanPort(result, port)
				if err != nil {
					// @todo - Create error channel
					return
				}
				if res.PortScan != nil {
					s.Results <- res
				}
			}()
		}
	}
	wg.Wait()
	close(s.Results)
}

// Start the scan
func (s *Scanner) Start(start, end uint32) {
	results := s.scanAsync(s.ips)
	s.portScanAsync(results, start, end)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.end = time.Now()
}

// Listen for results
func (s *Scanner) Listen() <-chan *Result {
	return s.Results
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
