package printer

import (
	"fmt"

	"github.com/EwanValentine/deepscan/pkg/scanner"
	"github.com/fatih/color"
)

// Scans defines the sub-set of
// methods needed for the printer
type Scans interface {
	Listen() <-chan *scanner.Result
	Close()
	OnStop() <-chan bool
	Stats() string
}

// Print takes the scanner and prints out the results
// with the correct formatting, and the does some
// clean-up operations when complete.
func Print(ds Scans) bool {
	for {
		select {
		case res := <-ds.Listen():
			color.Blue(fmt.Sprintf("Open: %s:%d", res.Addr, res.PortScan.Port))
			for _, host := range res.ReverseLookup {
				color.Blue(fmt.Sprintf("Host: %s", host))
			}
			fmt.Println(" ")

		case <-ds.OnStop():
			ds.Close()
			color.Blue("Complete...")
			color.Green(ds.Stats())
			return true
		}
	}
}
