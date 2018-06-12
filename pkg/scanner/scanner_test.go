package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanScanCIDRBlock(t *testing.T) {
	s := New()
	s.Target("192.168.1.1/24")
	assert.Equal(t, 254, len(s.ips))
	s.Start(80, 85)
	<-s.OnStop()
	assert.Equal(t, uint32(6)*uint32(len(s.ips)), s.portsScanned)
}

func TestCanScanSingleIP(t *testing.T) {
	s := New()
	s.Target("192.168.1.1")
	s.Start(80, 85)
	<-s.OnStop()
	assert.Equal(t, uint32(6), s.portsScanned)
}
