package license

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultLicense(t *testing.T) {
	lic := NewDefaultLicense()

	assert.Equal(t, rootKey.Bytes(), []byte(lic.Blocks[0].PublicKey))
	//fmt.Println(lic.Blocks)
}
