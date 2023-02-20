package license

import (
	"bytes"
	"encoding/binary"
)

type ServerBlock struct {
	// 01 bytes : Server License Type
	ServerLicenseType byte
	// 04 bytes : Unknown
	Unknown uint32
	//var bytes : A null terminated string, which describes the issuer of this certificate.
	Issuer string
}

func (s ServerBlock) Marshal() ([]byte, error) {
	unknown := make([]byte, 4)
	binary.BigEndian.PutUint32(unknown, s.Unknown)
	return bytes.Join([][]byte{{s.ServerLicenseType}, unknown[0:], []byte(s.Issuer), {0x00}}, []byte{}), nil
}

func (s ServerBlock) Unmarshal(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}

type EphemeralBlock struct{}

func (e EphemeralBlock) Marshal() ([]byte, error) {
	return []byte{}, nil
}

func (e EphemeralBlock) Unmarshal(i []byte) error {
	//TODO implement me
	panic("implement me")
}

func (s ServerBlock) isLicenseBlockContent()    {}
func (e EphemeralBlock) isLicenseBlockContent() {}

func NewServerBlock(t byte) ServerBlock {
	return ServerBlock{
		ServerLicenseType: t,
		Unknown:           32,
		Issuer:            "Anonymous",
	}
}

func NewEphemeralBlock() EphemeralBlock {
	return EphemeralBlock{}
}
