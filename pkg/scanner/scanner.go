package scanner

import (
	"fmt"
	"strings"
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

// Scanner is a generic interface to allow users
// to create multiple scanners
type Scanner interface {
	Host(ip string) (*Result, error)
	Port(result *Result, port uint32) (*Result, error)
}

type printer interface {
	Print(<-chan *Result, string)
}

type attacker interface {
	Attack(<-chan *Result)
}

// DeepScan is the main program
type DeepScan struct {
	Results chan *Result
	Scanner
	ips  []string
	quit chan struct{}
	mu   *sync.Mutex

	// Stats
	start        time.Time
	end          time.Time
	portsScanned uint32
	ipsScanned   uint32
	attacker
	printer
}

// New marks the beginning of operation and retunes a new instance of Scanner.
func New() *DeepScan {
	results := make(chan *Result, 1)
	quit := make(chan struct{})
	ips := []string{}
	mutex := &sync.Mutex{}
	thorough := &ThoroughScan{}
	return &DeepScan{
		Results: results,
		Scanner: thorough,
		ips:     ips,
		quit:    quit,
		start:   time.Now(),
		mu:      mutex,
	}
}

// SetAttacker allows for a custom attack type to be set
func (s *DeepScan) SetAttacker(attacker attacker) {
	s.mu.Lock()
	s.attacker = attacker
	s.mu.Unlock()
}

// SetPrinter allows for a customer printer type to be set
func (s *DeepScan) SetPrinter(printer printer) {
	s.mu.Lock()
	s.printer = printer
	s.mu.Unlock()
}

// Network allows for a network CIDR range to be set
func (s *DeepScan) network(cidr string) error {
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

// Target takes a single IP or a CIDR block
func (s *DeepScan) Target(ip string) {
	if strings.Contains(ip, "/") {
		s.network(ip)
		return
	}
	s.ips = []string{ip}
}

func (s *DeepScan) scan(ip string) (*Result, error) {
	s.mu.Lock()
	s.ipsScanned++
	s.mu.Unlock()
	return s.Scanner.Host(ip)
}

func (s *DeepScan) scanPort(result *Result, port uint32) (*Result, error) {
	s.mu.Lock()
	s.portsScanned++
	s.mu.Unlock()
	return s.Scanner.Port(result, port)
}

func (s *DeepScan) scanAsync(pipeline []string) <-chan *Result {
	out := make(chan *Result, len(s.ips))
	go func() {
		for _, ip := range pipeline {
			res, err := s.scan(ip)
			if err != nil {
				// @todo handle errors
				continue
			}
			if res != nil {
				out <- res
			}
		}
		close(out)
	}()
	return out
}

func (s *DeepScan) portScanAsync(input <-chan *Result, start, end uint32) {
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

// SetScanner allows the user to set a custom scanner
func (s *DeepScan) SetScanner(scanner Scanner) {
	s.Scanner = scanner
}

// Start the scan
func (s *DeepScan) Start(start, end uint32) {
	results := s.scanAsync(s.ips)
	s.portScanAsync(results, start, end)
	s.mu.Lock()
	s.end = time.Now()
	s.mu.Unlock()
}

// Print output with the given printer
func (s *DeepScan) Print() {
	s.printer.Print(s.Listen(), s.String())
}

// Attack found potential targets given potential attack type
func (s *DeepScan) Attack() {
	s.attacker.Attack(s.Listen())
}

// Listen for results
func (s *DeepScan) Listen() <-chan *Result {
	return s.Results
}

// String returns some stats
func (s *DeepScan) String() string {
	s.mu.Unlock()
	ipsScanned := s.ipsScanned
	portsScanned := s.portsScanned
	duration := s.end.Sub(s.start).Seconds()
	s.mu.Lock()

	return fmt.Sprintf(
		"Scanned %d ips and %d ports in %f seconds",
		ipsScanned,
		portsScanned,
		duration,
	)
}
