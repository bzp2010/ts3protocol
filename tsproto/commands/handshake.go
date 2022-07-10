package commands

import "github.com/bzp2010/ts3protocol/tsproto/packets"

func NewInitIVExpand2() packets.Command {
	return packets.Command{
		Name: "initivexpand2",
		Params: map[string]string{
			"l":     "",  // the server license
			"beta":  "",  // beta is base64(random[u8; 54]) by the server
			"omega": "",  // omega is base64(publicKey[u8]) with the public key from the server, encoded same as in clientinitiv
			"ot":    "1", // os should always be 1
			"proof": "",  // proof is a base64(ecdh_sign(l))
			"tvd":   "",  // tvd (base64, unknown; only set on servers with a license)
		},
	}
}
