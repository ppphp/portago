package atom

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDecodeInt(t *testing.T) {
	for i := 0; i < 1000;i++{
		assert.Equal(t, decodeint(encodeint(i)), i)
	}
	//for i := 0; i < 4294967296-1;i++{
	//	assert.Equal(t, decodeint(encodeint(i)), i)
	//}
}
