package scanner

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanScanCIDRBlock(t *testing.T) {
	s, err := New()
	assert.NoError(t, err)
	s.Network("192.168.1.1/24")
	assert.Equal(t, 254, len(s.ips))
	s.Start(80, 88)
	<-s.OnStop()
	log.Println("test", s.portsScanned)
	assert.Equal(t, uint32(8), s.portsScanned)
}
