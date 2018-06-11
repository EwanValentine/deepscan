package cmd

import (
	"time"

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

	single = kingpin.Command("single", "Single attack vector")
	ip     = single.Arg("ip", "IP target address").Required().String()

	multiple = kingpin.Command("multiple", "Multiple attack vectors")
	cidr     = multiple.Arg("cidr", "CIDR block").Required().String()
)

// Execute command line interface
func Execute() {
	kingpin.Version("0.0.1")
	kingpin.Parse()

	color.Red(title)
	color.Yellow(subTitle)

	switch kingpin.Parse() {
	case "single":
		s := spinner.New(spinner.CharSets[21], 100*time.Millisecond)
		s.Start()
		defer s.Stop()
		ds := scanner.New()
		start, end, err := ports.ConvertPortRange(*portRange)
		if err != nil {
			panic(err)
		}
		ds.Target(*ip)
		ds.Start(start, end)
		printer.Print(ds)

	case "multiple":
		s := spinner.New(spinner.CharSets[21], 100*time.Millisecond)
		s.Start()
		defer s.Stop()
		ds := scanner.New()
		ds.Network(*cidr)
		start, end, err := ports.ConvertPortRange(*portRange)
		if err != nil {
			panic(err)
		}
		ds.Start(start, end)
		printer.Print(ds)
	}
}
