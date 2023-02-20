package crypto

import (
	"bytes"
	"encoding/asn1"
	"math/big"
)

// ASN1Omega is a parameter of clientinitiv and initivexpand2 command
type ASN1Omega struct {
	BS         string
	KeySize    int32
	PublicKeyX *big.Int
	PublicKeyY *big.Int
}

func (o ASN1Omega) Encode() ([]byte, error) {
	bsByte := []byte(o.BS)
	bs, err := asn1.Marshal(asn1.BitString{
		Bytes:     bsByte,
		BitLength: len(bsByte),
	})
	if err != nil {
		return nil, err
	}
	keySize, err := asn1.Marshal(o.KeySize)
	if err != nil {
		return nil, err
	}
	publicKeyX, err := asn1.Marshal(o.PublicKeyX)
	if err != nil {
		return nil, err
	}
	publicKeyY, err := asn1.Marshal(o.PublicKeyY)
	if err != nil {
		return nil, err
	}
	raw, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      bytes.Join([][]byte{bs, keySize, publicKeyX, publicKeyY}, []byte{}),
	})
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func (o *ASN1Omega) Decode(raw []byte) error {
	var rawValue asn1.RawValue
	_, err := asn1.Unmarshal(raw, &rawValue)
	if err != nil {
		return err
	}

	var (
		bs         asn1.BitString
		keySize    int32
		publicKeyX *big.Int
		publicKeyY *big.Int
	)
	omega, err := asn1.Unmarshal(rawValue.Bytes, &bs)
	if err != nil {
		return err
	}
	omega, err = asn1.Unmarshal(omega, &keySize)
	if err != nil {
		return err
	}
	omega, err = asn1.Unmarshal(omega, &publicKeyX)
	if err != nil {
		return err
	}
	omega, err = asn1.Unmarshal(omega, &publicKeyY)
	if err != nil {
		return err
	}

	o.BS = string(bs.Bytes)
	o.KeySize = keySize
	o.PublicKeyX = publicKeyX
	o.PublicKeyY = publicKeyY

	return nil
}
