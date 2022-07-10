package packets

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"

	tsErrors "github.com/bzp2010/ts3protocol/tsproto/errors"
)

const (
	VersionTimestampDifference = 1356998400
)

type Init0Packet struct {
	C2SPacket
	// 04 bytes : Version of the TeamSpeak client as timestamp
	//            Example: { 0x06, 0x3b, 0xec, 0xe9 }
	VersionTimestamp uint32
	// 04 bytes : Current timestamp in unix format
	Timestamp uint32
	// 04 bytes : Random bytes := [A0]
	Random0 [4]byte
}

func (p Init0Packet) Marshal() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (p *Init0Packet) Unmarshal(raw []byte) error {
	if len(raw) != 34 {
		return errors.Errorf(tsErrors.PacketIncomplete, len(raw), "= 34")
	}

	// parse packet header
	err := p.C2SPacket.Unmarshal(raw)
	if err != nil {
		return err
	}
	if p.PacketType != 8 {
		return errors.Errorf(tsErrors.PacketTypeUnmatched, p.PacketType, 8)
	}

	// read data
	data := raw[13:34]
	if data[4] != 0 {
		return errors.Errorf(tsErrors.PacketLowInitDisorder, data[4], 0)
	}
	p.VersionTimestamp = binary.BigEndian.Uint32(data[0:4]) + VersionTimestampDifference
	p.Timestamp = binary.BigEndian.Uint32(data[5:9])
	p.Random0 = [4]byte{data[9], data[10], data[11], data[12]}
	return nil
}

type Init1Packet struct {
	S2CPacket
	// 04 bytes : The bytes from [A0] in reversed order (not always) := [A0r]
	// store the original data instead of the reversed
	Random0 [4]byte
	// 16 bytes : Server stuff := [A1]
	Random1 [16]byte
}

func (p Init1Packet) Marshal() ([]byte, error) {
	if p.S2CPacket.MAC == "" {
		FillLowInitPacketHeader(&p.S2CPacket)
	}

	data, err := p.S2CPacket.Marshal()
	if err != nil {
		return nil, err
	}

	data = bytes.Join([][]byte{data, {0x01}, p.Random1[0:], {p.Random0[3], p.Random0[2], p.Random0[1], p.Random0[0]}}, []byte{})
	return data, nil
}

func (p *Init1Packet) Unmarshal(pkg []byte) error {
	//TODO implement me
	panic("implement me")
}

type Init2Packet struct {
	C2SPacket
	// 04 bytes : Version of the TeamSpeak client as timestamp
	VersionTimestamp uint32
	// 04 bytes : The bytes from [A0r]
	// store the original data instead of the reversed
	Random0 [4]byte
	// 16 bytes : The bytes from [A1]
	Random1 [16]byte
}

func (p Init2Packet) Marshal() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (p *Init2Packet) Unmarshal(raw []byte) error {
	if len(raw) != 38 {
		return errors.Errorf(tsErrors.PacketIncomplete, len(raw), "= 38")
	}

	// parse packet header
	err := p.C2SPacket.Unmarshal(raw)
	if err != nil {
		return err
	}
	if p.PacketType != 8 {
		return errors.Errorf(tsErrors.PacketTypeUnmatched, p.PacketType, 8)
	}

	// read data
	data := raw[13:38]
	if data[4] != 2 {
		return errors.Errorf(tsErrors.PacketLowInitDisorder, data[4], 2)
	}
	p.VersionTimestamp = binary.BigEndian.Uint32(data[0:4]) + VersionTimestampDifference
	p.Random1 = *(*[16]byte)(data[5:21])
	p.Random0 = *(*[4]byte)(data[21:25])

	return nil
}

type Init3Packet struct {
	S2CPacket
	// 64 bytes : 'x', an unsigned BigInteger
	X [64]byte
	// 64 bytes : 'n', an unsigned BigInteger
	N [64]byte
	// 04 bytes : 'level' a u32
	Level uint32
	// 100 bytes : Server stuff := [A2]
	Random2 [100]byte
}

func (p Init3Packet) Marshal() ([]byte, error) {
	if p.S2CPacket.MAC == "" {
		FillLowInitPacketHeader(&p.S2CPacket)
	}

	data, err := p.S2CPacket.Marshal()
	if err != nil {
		return nil, err
	}

	levelByte := make([]byte, 4)
	binary.BigEndian.PutUint32(levelByte, p.Level)

	data = bytes.Join([][]byte{data, {0x03}, p.X[0:], p.N[0:], levelByte[0:4], p.Random2[0:]}, []byte{})
	return data, nil
}

func (p *Init3Packet) Unmarshal(pkg []byte) error {
	//TODO implement me
	panic("implement me")
}

type Init4Packet struct {
	C2SPacket
	// 04 bytes : Version of the TeamSpeak client as timestamp
	VersionTimestamp uint32
	// 64 bytes : the received 'x'
	X [64]byte
	// 64 bytes : the received 'n'
	N [64]byte
	// 04 bytes : the received 'level'
	Level uint32
	// 100 bytes: The bytes from [A2]
	Random2 [100]byte
	// 64 bytes : 'y' which is the result of x ^ (2 ^ level) % n as an unsigned
	//            BigInteger. Padded from the lower side with '0x00' when shorter
	//            than 64 bytes.
	//            Example: { 0x00, 0x00, data ... data}
	Y [64]byte
	// var bytes : The clientinitiv command data
	Data []byte
}

func (p Init4Packet) Marshal() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (p *Init4Packet) Unmarshal(raw []byte) error {
	if len(raw) <= 314 {
		return errors.Errorf(tsErrors.PacketIncomplete, len(raw), "> 314")
	}

	// parse packet header
	err := p.C2SPacket.Unmarshal(raw)
	if err != nil {
		return err
	}
	if p.PacketType != 8 {
		return errors.Errorf(tsErrors.PacketTypeUnmatched, p.PacketType, 8)
	}

	// read data
	data := raw[13:]
	if data[4] != 4 {
		return errors.Errorf(tsErrors.PacketLowInitDisorder, data[4], 4)
	}
	p.VersionTimestamp = binary.BigEndian.Uint32(data[0:4]) + VersionTimestampDifference
	p.X = *(*[64]byte)(data[5:69])
	p.N = *(*[64]byte)(data[69:133])
	p.Level = binary.BigEndian.Uint32(data[133:137])
	p.Random2 = *(*[100]byte)(data[137:237])
	p.Y = *(*[64]byte)(data[237:301])
	p.Data = data[301:]

	return nil
}

// FillLowInitPacketHeader for filling init series packets' consistent
// packet header structure
func FillLowInitPacketHeader(packet interface{}) {
	switch packet.(type) {
	case *C2SPacket:
		p := packet.(*C2SPacket)
		p.MAC = "TS3INIT1"
		p.PacketId = 101
		p.ClientId = 0
		p.Encrypted = false
		p.Compressed = false
		p.NewProtocol = false
		p.Fragmented = false
		p.PacketType = PacketTypeInit1
	case *S2CPacket:
		p := packet.(*S2CPacket)
		p.MAC = "TS3INIT1"
		p.PacketId = 101
		p.Encrypted = false
		p.Compressed = false
		p.NewProtocol = false
		p.Fragmented = false
		p.PacketType = PacketTypeInit1
	}
}
