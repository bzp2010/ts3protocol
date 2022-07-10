package packets

import (
	"strings"

	"github.com/pkg/errors"

	tsErrors "github.com/bzp2010/ts3protocol/tsproto/errors"
)

type CommandPacket struct {
	C2SPacket
	S2CPacket
	Command
}

type Command struct {
	Name   string
	Params CommandParams
}

type CommandParams map[string]string

func (c Command) Marshal() ([]byte, error) {
	var params []string
	for k, v := range c.Params {
		params = append(params, strings.Join([]string{k, v}, "="))
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
