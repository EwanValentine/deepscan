package cmd

import (
	"time"

	"github.com/EwanValentine/deepscan/pkg/attacks"
	"github.com/EwanValentine/deepscan/pkg/ports"
	"github.com/EwanValentine/deepscan/pkg/printer"
	"github.com/EwanValentine/deepscan/pkg/scanner"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const title = `
::::::::: :::::::::::::::::::::::::::::    ::::::::  ::::::::     :::    ::::    :::
:+:    :+::+:       :+:       :+:    :+:  :+:    :+::+:    :+:  :+: :+:  :+:+:   :+:
+:+    +:++:+       +:+       +:+    +:+  +:+       +:+        +:+   +:+ :+:+:+  +:+
+#+    +:++#++:++#  +#++:++#  +#++:++#+   +#++:++#+++#+       +#++:++#++:+#+ +:+ +#+
+#+    +#++#+       +#+       +#+                +#++#+       +#+     +#++#+  +#+#+#
#+#    #+##+#       #+#       #+#         #+#    #+##+#    #+##+#     #+##+#   #+#+#
######### #######################          ########  ######## ###     ######    ####
`

const subTitle = `
_, _ __, ___ _  _  _, __, _,_    _, _, _  _, _,  , _  _, _  _,   ___  _,  _, _, 
|\ | |_   |  |  | / \ |_) |_/   / \ |\ | /_\ |   \ | (_  | (_     |  / \ / \ |  
| \| |    |  |/\| \ / | \ | \   |~| | \| | | | ,  \| , ) | , )    |  \ / \ / | ,
~  ~ ~~~  ~  ~  ~  ~  ~ ~ ~ ~   ~ ~ ~  ~ ~ ~ ~~~   )  ~  ~  ~     ~   ~   ~  ~~~
												  ~'                            
`

var (
	app = kingpin.New("deep-scanner", "A deep network analysis tool.")

	portRange = kingpin.Flag("ports", "Port range 8080:8081").String()
	ip        = kingpin.Arg("ip", "IP target address").Required().String()
)

// Execute command line interface
func Execute() {
	kingpin.Version("0.0.1")
	kingpin.Parse()

	color.Red(title)
	color.Yellow(subTitle)

	s := spinner.New(spinner.CharSets[21], 100*time.Millisecond)
	s.Start()
	defer s.Stop()
	ds := scanner.New()
	start, end, err := ports.ConvertPortRange(*portRange)
	if err != nil {
		panic(err)
	}

	kingpin.Parse()

	// Scanner
	ds.Target(*ip)
	ds.Start(start, end)

	// Printer
	printer.Print(ds)

	// Attack
	attacks.DenialOfService(ds)
}
