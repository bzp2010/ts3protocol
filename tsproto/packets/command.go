package packets

import (
	"strings"

	"github.com/pkg/errors"

	tsErrors "github.com/bzp2010/ts3protocol/tsproto/errors"
)

type CommandPacket struct {
	PacketDirection
	C2S     *C2SPacket
	S2C     *S2CPacket
	Command *Command
}

func (cp CommandPacket) Marshal() ([]byte, error) {
	var (
		header []byte
		body   []byte
		err    error
	)

	// header
	if cp.C2S != nil {
		header, err = cp.C2S.Marshal()
	} else {
		header, err = cp.S2C.Marshal()
	}
	if err != nil {
		return nil, err
	}

	// body
	body, err = cp.Command.Marshal()
	if err != nil {
		return nil, err
	}

	return append(header, body...), nil
}

func (cp *CommandPacket) Unmarshal(bytes []byte) error {
	var (
		dataOffset int
		err        error
	)

	if cp.Direction() == PacketDirectionC2S {
		dataOffset = 13
		cp.C2S = &C2SPacket{}
		err = cp.C2S.Unmarshal(bytes)
	} else {
		dataOffset = 11
		cp.S2C = &S2CPacket{}
		err = cp.S2C.Unmarshal(bytes)
	}

	if err != nil {
		return err
	}

	cp.Command = &Command{}
	err = cp.Command.Unmarshal(bytes[dataOffset:])
	if err != nil {
		return err
	}

	return nil
}

func (cp CommandPacket) isPacket() {}

type Command struct {
	Name   string
	Params CommandParams
}

type CommandParams map[string]string

func (c Command) Marshal() ([]byte, error) {
	var params []string
	for k, v := range c.Params {
		if v != "" {
			val := strings.NewReplacer(
				"\u000b", "\\v",
				"\u000c", "\\f",
				"\t", "\\t",
				"\r", "\\r",
				"\n", "\\n",
				"|", "\\p",
				" ", "\\s",
				"/", "\\/",
				"\\", "\\\\",
			).Replace(v)
			params = append(params, strings.Join([]string{k, val}, "="))
		} else {
			params = append(params, k)
		}
	}
	return []byte(c.Name + " " + strings.Join(params, " ")), nil
}

func (c *Command) Unmarshal(raw []byte) error {
	part := strings.Split(string(raw), " ")
	if len(part) <= 0 {
		return errors.Errorf(tsErrors.InvalidCommand, "empty command payload")
	}

	c.Name = part[0]
	c.Params = make(map[string]string)
	for i := 1; i < len(part); i++ {
		paramKV := strings.SplitN(part[i], "=", 2)
		if len(paramKV) == 2 {
			val := strings.NewReplacer(
				"\\v", "\u000b",
				"\\f", "\u000c",
				"\\t", "\t",
				"\\r", "\r",
				"\\n", "\n",
				"\\p", "|",
				"\\s", " ",
				"\\/", "/",
				"\\\\", "\\",
			).Replace(paramKV[1])
			c.Params[paramKV[0]] = val
		} else if len(paramKV) == 1 {
			c.Params[paramKV[0]] = ""
		}
	}
	return nil
}
