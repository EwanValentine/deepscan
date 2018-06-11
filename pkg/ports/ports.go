package ports

import (
	"errors"
	"strconv"
	"strings"
)

// ConvertPortRange converts a port pair such as 8080:9000
// into its seprate numbers as integers
func ConvertPortRange(portRange string) (uint32, uint32, error) {
	ports := strings.Split(portRange, ":")
	if len(ports) != 2 {
		return 0, 0, errors.New("incorrect format")
	}
	start, err := strconv.ParseUint(ports[0], 10, 32)
	if err != nil {
		return 0, 0, err
	}

	end, err := strconv.ParseUint(ports[1], 10, 32)
	if err != nil {
		return 0, 0, err
	}
	return uint32(start), uint32(end), nil
}
