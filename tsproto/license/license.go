package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strconv"

	"filippo.io/edwards25519"

	"github.com/bzp2010/ts3protocol/tsproto/packets"
)

const (
	ValidDataDifference = 1356998400
)

var (
	rootKey, _ = (&edwards25519.Point{}).SetBytes([]byte{
		0xcd, 0x0d, 0xe2, 0xae, 0xd4, 0x63, 0x45, 0x50,
		0x9a, 0x7e, 0x3c, 0xfd, 0x8f, 0x68, 0xb3, 0xdc,
		0x75, 0x55, 0xb2, 0x9d, 0xcc, 0xec, 0x73, 0xcd,
		0x18, 0x75, 0x0f, 0x99, 0x38, 0x12, 0x40, 0x8a,
	})
)

// NewDefaultLicense will create an empty license that contains only Server and Ephemeral
func NewDefaultLicense() License {
	license := License{
		LicenseVersion: 0x01,
	}

	// Add Server block
	license.AddLicenseBlock(Block{
		BlockType:        2,
		MinimumValidData: ValidDataDifference,
		MaximumValidData: 4294967295,
		Content:          NewServerBlock(7),
	})

	// Add Ephemeral block
	license.AddLicenseBlock(Block{
		BlockType:        32,
		MinimumValidData: ValidDataDifference,
		MaximumValidData: 4294967295,
		Content:          NewEphemeralBlock(),
	})

	return license
}

type License struct {
	// 01 bytes : License version
	//            Const: 0x01
	LicenseVersion byte
	Blocks         []Block
}

type fixedReader struct {
	Value []byte
}

func (f fixedReader) Read(p []byte) (n int, err error) {
	copy(p, f.Value)
	return len(p), nil
}

func (l *License) nextKeypair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	var (
		parent = new(edwards25519.Point).Set(rootKey) // Next publicKey
		b      []byte                                 // Raw block data
		scalar *edwards25519.Scalar                   // Generated privateKey
		//point  *edwards25519.Point
		err error
	)

	fmt.Println("计算Keypair, License块数量", len(l.Blocks))

	for i, block := range l.Blocks {
		fmt.Println("计算Keypair, License块数量", len(l.Blocks), "当前第"+strconv.Itoa(i+1)+"块")
		b, err = block.Marshal()
		if err != nil {
			return nil, nil, err
		}

		hash := sha512.Sum512(b[1:])
		scalar, err = new(edwards25519.Scalar).SetBytesWithClamping(hash[:32])
		if err != nil {
			panic(err)
		}

		currentPoint, err := new(edwards25519.Point).SetBytes(block.PublicKey)
		if err != nil {
			panic(err)
		}
		nextPoint := currentPoint.ScalarMult(scalar, currentPoint)
		parent = parent.Add(nextPoint, parent)

		fmt.Print("当前点")
		fmt.Println(currentPoint.ExtendedCoordinates())
		fmt.Print("下一个点 ")
		fmt.Println(parent.ExtendedCoordinates())
	}

	return scalar.Bytes(), parent.Bytes(), nil

	/*for _, block := range l.Blocks {
		b, err = block.Marshal()
		if err != nil {
			return nil, nil, err
		}

		privateKey = *(*[32]byte)(b[1:])
		privateKey[0] &= 248
		privateKey[31] &= 127
		privateKey[31] |= 64

		// Generate relative public key
		curve25519.ScalarBaseMult(&publicKey, &privateKey)

		next, err := curve25519.X25519(privateKey[:], publicKey[:])
		if err != nil {
			return nil, nil, err
		}

		nextPoint, err := new(edwards25519.Point).SetBytes(next)
		parent = nextPoint.Add(nextPoint, parent)
		parent.Bytes()
		fmt.Print("下一个点 ")
		fmt.Println(parent.ExtendedCoordinates())
	}*/
}

// AddLicenseBlock will add a block to license
// The input block needs to contain BlockType, MinimumValidData, MaximumValidData and Content data
func (l *License) AddLicenseBlock(b Block) {
	ptr := &b
	ptr.KeyType = 0x00
	ptr.MinimumValidData = ptr.MinimumValidData - ValidDataDifference
	ptr.MaximumValidData = ptr.MaximumValidData - ValidDataDifference

	// Only the first block just inserted (proving that it is the first in this License)
	if len(l.Blocks) == 0 {
		ptr.PublicKey = rootKey.Bytes()
	} else {
		_, nextPublicKey, err := l.nextKeypair()
		if err != nil {
			panic(err)
		}
		ptr.PublicKey = nextPublicKey
	}
	l.Blocks = append(l.Blocks, *ptr)
}

func (l *License) Marshal() ([]byte, error) {
	data := []byte{l.LicenseVersion}
	for _, block := range l.Blocks {
		b, err := block.Marshal()
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
	}
	return data, nil
}

// GetServerEK returns the keypair corresponding to the License.
// The client uses it as serverEK, the Ed25519 public key of the server, to implement ECDH key exchange.
func (l *License) GetServerEK() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privateKey, publicKey, err := l.nextKeypair()
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

// Block part of License
type Block struct {
	// 01 bytes : Key type
	//            Const: 0x00
	KeyType byte
	// 32 bytes : Block public key
	PublicKey ed25519.PublicKey
	// 01 bytes : License block type
	BlockType byte
	// 04 bytes : Not valid before date
	MinimumValidData uint32
	// 04 bytes : Not valid after date
	MaximumValidData uint32
	// var bytes : (Content from the block type)
	Content BlockContent
}

func (b Block) Marshal() ([]byte, error) {
	minimum := make([]byte, 4)
	binary.BigEndian.PutUint32(minimum, b.MinimumValidData)

	maximum := make([]byte, 4)
	binary.BigEndian.PutUint32(maximum, b.MaximumValidData)

	content, err := b.Content.Marshal()
	if err != nil {
		return nil, err
	}

	return bytes.Join([][]byte{{b.KeyType}, b.PublicKey, {b.BlockType}, minimum, maximum, content}, []byte{}), nil
}

func (b Block) Unmarshal(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}

type BlockContent interface {
	packets.Marshaler
	packets.Unmarshaler
	isLicenseBlockContent()
}
