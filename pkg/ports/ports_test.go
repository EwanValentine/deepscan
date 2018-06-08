package ports

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanSplitPortPair(t *testing.T) {
	pair := "8080:9090"
	start, end, err := ConvertPortRange(pair)
	assert.NoError(t, err)
	assert.Equal(t, uint32(8080), start)
	assert.Equal(t, uint32(9090), end)
}
