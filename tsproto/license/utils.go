package license

import "crypto/sha512"

func licenseHash(data []byte) []byte {
	s := sha512.Sum512(data)
	return s[:32]
}
