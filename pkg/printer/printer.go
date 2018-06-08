package printer

import (
	"fmt"

	"github.com/EwanValentine/deepscan/pkg/scanner"
	"github.com/fatih/color"
)

// Print takes the scanner and prints out the results
// with the correct formatting, and the does some
// clean-up operations when complete.
func Print(ds *scanner.Scanner) bool {
	for {
		select {
		case res := <-ds.Listen():
			for _, port := range res.PortScan {
				color.Blue(fmt.Sprintf("Open: %s:%d", res.Addr, port.Port))
			}
			for _, host := range res.ReverseLookup {
				color.Blue(fmt.Sprintf("Host: %s", host))
			}
			fmt.Println(" ")

		case <-ds.OnStop():
			ds.Close()
			color.Blue("Complete...")
			return true
		}
	}
}
