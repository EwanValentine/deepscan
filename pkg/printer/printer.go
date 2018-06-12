package printer

import (
	"fmt"

	"github.com/EwanValentine/deepscan/pkg/scanner"
	"github.com/fatih/color"
)

// Scans defines the sub-set of
// methods needed for the printer
type scans interface {
	Listen() <-chan *scanner.Result
	String() string
}

// Print takes the scanner and prints out the results
// with the correct formatting, and the does some
// clean-up operations when complete.
func Print(ds scans) bool {
	for {
		select {
		case res, more := <-ds.Listen():
			if !more {
				color.Blue("Complete...")
				color.Green(ds.String())
				return true
			}
			color.Blue(fmt.Sprintf("Open: %s:%d", res.Addr, res.PortScan.Port))
			for _, host := range res.ReverseLookup {
				color.Blue(fmt.Sprintf("Host: %s", host))
			}
			fmt.Println(" ")
		}
	}
}
