package main

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/ProtonMail/go-crypto/eax"
	gofsm "github.com/looplab/fsm"

	"github.com/bzp2010/ts3protocol/tsproto/license"
	"github.com/bzp2010/ts3protocol/tsproto/packets"
)

var (
	defaultKey   = []byte{0x63, 0x3A, 0x5C, 0x77, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x5C, 0x73, 0x79, 0x73, 0x74, 0x65}
	defaultNonce = []byte{0x6D, 0x5C, 0x66, 0x69, 0x72, 0x65, 0x77, 0x61, 0x6C, 0x6C, 0x33, 0x32, 0x2E, 0x63, 0x70, 0x6C}
)

type client struct {
	*gofsm.FSM
	Conn          *net.UDPConn
	RemoteAddr    *net.UDPAddr
	PacketCounter *packetCounter

	SharedIV  []byte
	SharedMAC []byte

	ServerPrivateKey     ed25519.PrivateKey
	ClientOmegaPublicKey *ecdsa.PublicKey
	TempAlpha            []byte
	TempBeta             []byte
	TempLicense          *license.License
}

func (c client) Send(p packets.Packet) error {
	var (
		headerRaw []byte
		bodyRaw   []byte
	)

	switch p.(type) {
	case *packets.CommandPacket:
		cp := p.(*packets.CommandPacket)
		fmt.Println("准备发送Command数据包", cp.Command.Name, cp.Command.Params)
		headerRaw, _ = cp.S2C.Marshal()
		bodyRaw, _ = cp.Command.Marshal()
		if cp.S2C.Encrypted {
			headerRaw, bodyRaw = encrypt(headerRaw, bodyRaw)
		}

	case *packets.AckPacket:
		ap := p.(*packets.AckPacket)
		fmt.Println("准备发送Ack数据包")
		headerRaw, _ = ap.S2C.Marshal()
		bodyRaw = make([]byte, 2)
		binary.BigEndian.PutUint16(bodyRaw, ap.PacketId)
		if ap.S2C.Encrypted {
			headerRaw, bodyRaw = encrypt(headerRaw, bodyRaw)
		}
	}

	_, err := c.Conn.WriteToUDP(append(headerRaw, bodyRaw...), c.RemoteAddr)
	if err != nil {
		return err
	}

	return nil
}

func (c client) SendAck(sourcePacketId uint16) error {
	ack := &packets.AckPacket{
		S2C: &packets.S2CPacket{
			PacketId:    0,
			Encrypted:   true,
			NewProtocol: true,
			PacketType:  packets.PacketTypeAck,
		},
		PacketId: sourcePacketId,
	}
	return c.Send(ack)
}

func encrypt(headerRaw, bodyRaw []byte) ([]byte, []byte) {
	block, _ := aes.NewCipher(defaultKey)
	aead, _ := eax.NewEAXWithNonceAndTagSize(block, 16, 8)
	ret := aead.Seal([]byte{}, defaultNonce, bodyRaw, headerRaw[8:])
	for i := 0; i < 8; i++ {
		headerRaw[i] = ret[len(bodyRaw)+i]
	}
	bodyRaw = ret[:len(bodyRaw)]
	return headerRaw, bodyRaw
}
