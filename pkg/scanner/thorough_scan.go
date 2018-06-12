package scanner

import (
	"fmt"
	"net"
	"time"
)

// ThoroughScan scans each host and port
// by checking each host, then attempting
// to connect to each host it finds with each port in rage
type ThoroughScan struct{}

// Host scans the ip address
func (scanner *ThoroughScan) Host(ip string) (*Result, error) {

	// Scan each ip address for an active host
	reverse, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}

	host, err := net.LookupHost(ip)
	if err != nil {
		return nil, err
	}

	cname, err := net.LookupCNAME(ip)
	if err != nil {
		return nil, err
	}

	return &Result{
		Hosts:         host,
		ReverseLookup: reverse,
		Cname:         cname,
		Addr:          ip,
	}, nil
}

// Port scans a port
func (scanner *ThoroughScan) Port(result *Result, port uint32) (*Result, error) {
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
