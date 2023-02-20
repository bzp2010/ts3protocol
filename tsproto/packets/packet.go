package packets

import (
	"encoding/binary"
)

type PacketType int8
type PacketDirection int8

const (
	PacketTypeVoice        PacketType      = 0
	PacketTypeVoiceWhisper PacketType      = 1
	PacketTypeCommand      PacketType      = 2
	PacketTypeCommandLow   PacketType      = 3
	PacketTypePing         PacketType      = 4
	PacketTypePong         PacketType      = 5
	PacketTypeAck          PacketType      = 6
	PacketTypeAckLow       PacketType      = 7
	PacketTypeInit1        PacketType      = 8
	PacketDirectionC2S     PacketDirection = 0
	PacketDirectionS2C     PacketDirection = 1
)

func (pd PacketDirection) Direction() PacketDirection {
	return pd
}

// Marshaler for Packet
type Marshaler interface {
	Marshal() ([]byte, error)
}

// Unmarshaler for Packet
type Unmarshaler interface {
	Unmarshal([]byte) error
}

type Packet interface {
	Marshaler
	Unmarshaler
	isPacket()
}

// C2SPacket is client to server packet
type C2SPacket struct {
	MAC         string
	PacketId    uint16
	ClientId    uint16
	Encrypted   bool
	Compressed  bool
	NewProtocol bool
	Fragmented  bool
	PacketType  PacketType
}

func (p C2SPacket) Marshal() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (p *C2SPacket) Unmarshal(raw []byte) error {
	p.MAC = string(raw[0:8])
	p.PacketId = binary.BigEndian.Uint16(raw[8:10])
	p.ClientId = binary.BigEndian.Uint16(raw[10:12])

	// parse packet type and flags
	p.MAC = string(raw[0:8])
	p.PacketId = binary.BigEndian.Uint16(raw[8:10])
	p.ClientId = binary.BigEndian.Uint16(raw[10:12])

	// parse packet type and flags
	pt := raw[12]
	p.Encrypted = pt>>7&1 == 0
	p.Compressed = pt>>6&1 == 1
	p.NewProtocol = pt>>5&1 == 1
	p.Fragmented = pt>>4&1 == 1
	p.PacketType = PacketType(pt & ((1 << 4) - 1))
	return nil
}

// S2CPacket is server to client packet
type S2CPacket struct {
	MAC         string
	PacketId    uint16
	Encrypted   bool
	Compressed  bool
	NewProtocol bool
	Fragmented  bool
	PacketType  PacketType
}

func (p S2CPacket) Marshal() ([]byte, error) {
	if len(p.MAC) < 8 {
		p.MAC = "00000000"
	}
	data := append([]byte(p.MAC), byte(p.PacketId>>8), byte(p.PacketId&0xff))

	var pt uint8
	if p.Encrypted {
		pt = 0b0
	} else {
		pt = 0b1
	}
	if p.Compressed {
		pt = pt<<1 + 1
	} else {
		pt = pt<<1 + 0
	}
	if p.NewProtocol {
		pt = pt<<1 + 1
	} else {
		pt = pt<<1 + 0
	}
	if p.Fragmented {
		pt = pt<<1 + 1
	} else {
		pt = pt<<1 + 0
	}
	pt = pt<<4 + uint8(p.PacketType)

	data = append(data, pt)

	return data, nil
}

func (p S2CPacket) Unmarshal(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}
