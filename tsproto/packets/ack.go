package packets

import "encoding/binary"

type AckPacket struct {
	C2S      *C2SPacket
	S2C      *S2CPacket
	PacketId uint16
}

func (ap AckPacket) Marshal() ([]byte, error) {
	var (
		header []byte
		pid    []byte
		err    error
	)
	if ap.C2S != nil {
		header, err = ap.C2S.Marshal()
	} else {
		header, err = ap.C2S.Marshal()
	}
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(pid, ap.PacketId)
	return append(header, pid...), nil
}

func (ap AckPacket) Unmarshal(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}

func (ap AckPacket) isPacket() {}
