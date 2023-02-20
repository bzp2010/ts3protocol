package commands

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	ts3Crypto "github.com/bzp2010/ts3protocol/tsproto/crypto"
	"github.com/bzp2010/ts3protocol/tsproto/license"
	"github.com/bzp2010/ts3protocol/tsproto/packets"
)

func NewInitIVExpand2(license license.License, privateKey *ecdsa.PrivateKey) (*packets.Command, error) {
	// marshal license
	l, err := license.Marshal()
	if err != nil {
		return nil, err
	}

	// generate beta
	beta := make([]byte, 54)
	_, err = rand.Read(beta)
	if err != nil {
		return nil, err
	}

	// encode public key
	o := &ts3Crypto.ASN1Omega{
		BS:         "0",
		KeySize:    32,
		PublicKeyX: privateKey.X,
		PublicKeyY: privateKey.Y,
	}
	omega, err := o.Encode()
	if err != nil {
		return nil, err
	}

	// proof
	hash := sha256.Sum256(l)
	proof, err := privateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &packets.Command{
		Name: "initivexpand2",
		Params: map[string]string{
			"l":     base64.StdEncoding.EncodeToString(l),     // the server license
			"beta":  base64.StdEncoding.EncodeToString(beta),  // beta is base64(random[u8; 54]) by the server
			"omega": base64.StdEncoding.EncodeToString(omega), // omega is base64(publicKey[u8]) with the public key from the server, encoded same as in clientinitiv
			"ot":    "1",                                      // ot should always be 1
			"proof": base64.StdEncoding.EncodeToString(proof), // proof is a base64(ecdh_sign(l))
			"tvd":   "",                                       // tvd (base64, unknown; only set on servers with a license)
		},
	}, nil
}
