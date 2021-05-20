package atom

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeInt(t *testing.T) {
	for i := 0; i < 1000; i++ {
		assert.Equal(t, decodeint(encodeint(i)), i)
	}
	//for i := 0; i < 4294967296-1;i++{
	//	assert.Equal(t, decodeint(encodeint(i)), i)
	//}
}
