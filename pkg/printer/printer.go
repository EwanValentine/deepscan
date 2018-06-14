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

// StdPrinter prints to terminal output
type StdPrinter struct{}

// Print takes the scanner and prints out the results
// with the correct formatting, and the does some
// clean-up operations when complete.
func (printer *StdPrinter) Print(results <-chan *scanner.Result, stats string) {
	for {
		select {
		case res, more := <-results:
			if !more {
				color.Blue("Complete...")
				color.Green(stats)
				return
			}
			color.Blue(fmt.Sprintf("Open: %s:%d", res.Addr, res.PortScan.Port))
			for _, host := range res.ReverseLookup {
				color.Blue(fmt.Sprintf("Host: %s", host))
			}
			fmt.Println(" ")
		}
	}
}
