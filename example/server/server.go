package main

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"os"

	"filippo.io/edwards25519"
	"github.com/ProtonMail/go-crypto/eax"
	gofsm "github.com/looplab/fsm"

	"github.com/bzp2010/ts3protocol/tsproto/commands"
	"github.com/bzp2010/ts3protocol/tsproto/crypto"
	"github.com/bzp2010/ts3protocol/tsproto/license"
	"github.com/bzp2010/ts3protocol/tsproto/packets"
)

type packetCounter struct {
	Command       uint16
	CommandGen    uint32
	CommandLow    uint16
	CommandLowGen uint32
	Ack           uint16
	AckGen        uint32
	AckLow        uint16
	AckLowGen     uint32
}

var (
	clientMap = make(map[string]*client)
)

func main() {
	/*l := license.NewDefaultLicense()
	ld, _ := l.Marshal()
	fmt.Println(l)
	fmt.Println(base64.StdEncoding.EncodeToString(ld))

	return*/

	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:9987")
	if err != nil {
		fmt.Println("Can't resolve address: ", err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	defer conn.Close()
	for {
		handleClient(conn)
	}
}

func handleClient(conn *net.UDPConn) {
	// read udp data
	data := make([]byte, 500)
	n, remoteAddr, err := conn.ReadFromUDP(data)
	if err != nil {
		fmt.Println("failed to read UDP msg because of ", err.Error())
		return
	}

	if _, ok := clientMap[remoteAddr.String()]; !ok {
		fmt.Println("为", remoteAddr, "创建客户端实例")
		clientMap[remoteAddr.String()] = &client{
			FSM:        newFSM(),
			Conn:       conn,
			RemoteAddr: remoteAddr,
		}
	}

	client := clientMap[remoteAddr.String()]

	// parse C2S packet
	c2sp := &packets.C2SPacket{}
	_ = c2sp.Unmarshal(data[:n])

	if (client.FSM.Is("LOW_START") || client.FSM.Is("LOW_P1") || client.FSM.Is("LOW_P3")) && c2sp.MAC != "TS3INIT1" {
		//fmt.Println("状态机状态错误，忽略数据包")
		return
	}
	if c2sp.PacketType == packets.PacketTypeAck {
		fmt.Println("接收到一个ACK包")
		return
	}

	fmt.Println("-------------------------------")
	fmt.Println("RECEIVE", n, remoteAddr /*c2sp*/)

	switch client.FSM.Current() {
	case "LOW_START": // 初始状态，处理INIT0包
		fmt.Println("PROCESS LOW_START")
		init0 := &packets.Init0Packet{}
		err := init0.Unmarshal(data[:n])
		if err != nil {
			fmt.Println("接收到错误INIT0", err)
			os.Exit(0)
		}
		fmt.Println("接收到INIT0", init0)

		//a0 := c2sp.Data[9:13]
		random1 := make([]byte, 16)
		rand.Read(random1)
		init1 := &packets.Init1Packet{
			Random0: init0.Random0,
			Random1: *(*[16]byte)(random1),
		}
		init1raw, err := init1.Marshal()
		if err != nil {
			fmt.Println("编码出错误INIT1", err)
		}
		fmt.Println("发响应INIT1", init1, init1raw)
		conn.WriteToUDP(init1raw, remoteAddr)
		client.FSM.Event("E_LOW_P0")
	case "LOW_P1": // 处理INIT2包
		fmt.Println("PROCESS LOW_P1")
		init2 := &packets.Init2Packet{}
		err := init2.Unmarshal(data[:n])
		if err != nil {
			fmt.Println("接收到错误INIT2", err)
			os.Exit(0)
		}
		fmt.Println("接收到INIT2", init2)

		// generate random value
		stuff := make([]byte, 100)
		rand.Read(stuff)
		x := make([]byte, 64)
		rand.Read(x)
		n := make([]byte, 64)
		rand.Read(n)
		// use a fixed level value
		level := uint32(10000)

		init3 := &packets.Init3Packet{
			X:       *(*[64]byte)(x),
			N:       *(*[64]byte)(n),
			Level:   level,
			Random2: *(*[100]byte)(stuff),
		}

		//fmt.Println("服务器生成的X值", (&big.Int{}).SetBytes(x[0:]))
		//fmt.Println("服务器生成的N值", (&big.Int{}).SetBytes(n[0:]))
		//fmt.Println("服务器生成的L值", level)

		init3raw, err := init3.Marshal()
		if err != nil {
			fmt.Println("编码出错误INIT3", err)
		}
		fmt.Println("发响应INIT3", init3, init3raw)
		conn.WriteToUDP(init3raw, remoteAddr)
		client.FSM.Event("E_LOW_P2")
	case "LOW_P3":
		fmt.Println("PROCESS LOW_P3")
		init4 := &packets.Init4Packet{}
		err := init4.Unmarshal(data[:n])
		if err != nil {
			fmt.Println("接收到错误INIT4", err)
			os.Exit(0)
		}
		fmt.Println("接收到INIT4", init4)

		// check puzzle result
		x := &big.Int{}
		x.SetBytes(init4.X[0:])
		n := &big.Int{}
		n.SetBytes(init4.N[0:])
		y := &big.Int{}
		y.SetBytes(init4.Y[0:])
		level := init4.Level

		//fmt.Println("客户端发回的X值", x)
		//fmt.Println("客户端发回的N值", n)
		//fmt.Println("客户端发回的L值", level)

		// t = 2 ^ level
		t := (&big.Int{}).Exp(big.NewInt(2), big.NewInt(int64(level)), nil)
		// cy = x ^ t % n
		cy := x.Exp(x, t, n)

		//fmt.Println("客户端发回的Y值", y)
		//fmt.Println("解算PUZZLE结果", cy)
		if y.Cmp(cy) != 0 {
			fmt.Println("解算PUZZLE校验失败")
			os.Exit(0)
		}

		// parse clientinitiv command
		fmt.Println(string(init4.Data))
		cmd := &packets.Command{}
		err = cmd.Unmarshal(init4.Data)
		if err != nil {
			fmt.Println("接收到错误INIT4CMD.", err)
			os.Exit(0)
		}
		fmt.Println("接收到INIT4.CMD", cmd)
		client.TempAlpha, _ = base64.StdEncoding.DecodeString(cmd.Params["alpha"])
		omegaRaw, err := base64.StdEncoding.DecodeString(cmd.Params["omega"])
		if err != nil {
			fmt.Println("BASE64解码Omega错误", err)
			os.Exit(0)
		}

		omega := crypto.ASN1Omega{}
		err = omega.Decode(omegaRaw)
		if err != nil {
			fmt.Println("ASN1 Omega解码错误", err)
			os.Exit(0)
		}
		fmt.Println("接收到Omega数据", omega)

		clientPublicKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     omega.PublicKeyX,
			Y:     omega.PublicKeyY,
		}
		fmt.Println("客户端clientinitiv公钥", clientPublicKey)
		client.ClientOmegaPublicKey = clientPublicKey

		serverPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println("服务器私钥生成错误", err)
			os.Exit(0)
		}
		fmt.Println("服务端私钥", serverPrivateKey)

		lic := license.NewDefaultLicense()
		licMarshaled, err := lic.Marshal()
		fmt.Println("服务器License", licMarshaled)
		point, _ := new(edwards25519.Point).SetBytes(lic.Blocks[len(lic.Blocks)-1].PublicKey)
		fmt.Println(point.ExtendedCoordinates())
		//client.ServerPrivateKey =
		/*s, err := edwards25519.NewScalar().SetBytesWithClamping(*lic.GetServerEKPrivateKey())
		client.ServerPrivateKey = s.Bytes()
		if err != nil {
			fmt.Println("生成ServerEKPrivateKey失败", err)
		}*/
		var serverPublicKey ed25519.PublicKey
		client.ServerPrivateKey, serverPublicKey = lic.GetServerEK()
		fmt.Print("服务器EK公钥")
		fmt.Println(serverPublicKey)

		initivexpand2, err := commands.NewInitIVExpand2(lic, serverPrivateKey)
		if err != nil {
			fmt.Println("创建InitIVExpand2命令失败", err)
		}
		client.TempBeta, _ = base64.StdEncoding.DecodeString(initivexpand2.Params["beta"])
		initivexpand2Packet := packets.CommandPacket{
			S2C: &packets.S2CPacket{
				PacketId:    0,
				Encrypted:   true,
				Compressed:  false,
				NewProtocol: true,
				Fragmented:  false,
				PacketType:  packets.PacketTypeCommand,
			},
			Command: initivexpand2,
		}
		fmt.Println("生成initivexpand2命令", initivexpand2Packet)
		err = client.Send(&initivexpand2Packet)
		if err != nil {
			fmt.Println("发响应initivexpand2失败", err)
		}
		client.FSM.Event("E_HIGH_ClientInitIV")
	case "HIGH_InitIVExpand":
		fmt.Println("接收到clientek原始数据", data[:n], "头部为", data[:13])

		block, _ := aes.NewCipher(defaultKey)
		aead, _ := eax.NewEAXWithNonceAndTagSize(block, 16, 8)
		ret, err := aead.Open([]byte{}, defaultNonce, bytes.Join([][]byte{data[13:n], data[0:8]}, []byte{}), data[8:13])
		if err != nil {
			fmt.Println("数据包解密错误", err)
			os.Exit(0)
		}
		fmt.Println("数据包解密后原始数据", string(ret))
		cmd := &packets.Command{}
		err = cmd.Unmarshal(ret)
		if err != nil {
			fmt.Println("接收到错误clientek", err)
			os.Exit(0)
		}
		fmt.Println("接收到", cmd.Name, "命令，参数为", cmd.Params)
		if cmd.Name != "clientek" {
			fmt.Println("接收到非clientek命令")
			os.Exit(0)
		}
		clientEK, err := base64.StdEncoding.DecodeString(cmd.Params["ek"])
		if err != nil {
			fmt.Println("clientek ek base64解码错误", err)
			os.Exit(0)
		}
		fmt.Println("接收到 ek，长度为", len(clientEK))
		proof, err := base64.StdEncoding.DecodeString(cmd.Params["proof"])
		if err != nil {
			fmt.Println("clientek proof base64解码错误", err)
			os.Exit(0)
		}
		//fmt.Println("接收到proof", string(proof))

		// 按规则拼接proof原始值并进行hash
		proofRaw := bytes.Join([][]byte{clientEK, client.TempBeta}, []byte{})
		hash := sha256.Sum256(proofRaw)

		verifyRet := ecdsa.VerifyASN1(client.ClientOmegaPublicKey, hash[:], proof)
		if !verifyRet {
			fmt.Println("proof签名校验失败")
			os.Exit(0)
		}
		fmt.Println("proof签名校验通过")

		// 计算 SharedIV 和 SharedMAC
		client.SharedIV, client.SharedMAC, err = sharedSecret(client.ServerPrivateKey, clientEK, client.TempAlpha, client.TempBeta)
		if err != nil {
			fmt.Println("计算SharedIV等失败", err)
		}
		fmt.Println("计算SharedIV", client.SharedIV, "SharedMAC", []byte(client.SharedMAC))

		_ = client.SendAck(c2sp.PacketId)
		client.FSM.Event("E_HIGH_ClientEK")
	case "HIGH_ClientInit":
		fmt.Println("接收到clientinit原始数据", data[:n], "头部为", data[:13])
		cp := &packets.CommandPacket{}
		err := cp.Unmarshal(data[:n])
		if err != nil {
			fmt.Println("解码clientinit错误", err)
		}

		key, nonce := calculateKeyAndNonce(packets.PacketTypeCommand, cp.C2S.PacketId, 0, packets.PacketDirectionC2S, client.SharedIV)

		block, _ := aes.NewCipher(key)
		aead, _ := eax.NewEAXWithNonceAndTagSize(block, 16, 8)
		ret, err := aead.Open([]byte{}, nonce, append(data[13:n], data[0:8]...), data[8:13])
		if err != nil {
			fmt.Println("数据包解密错误", err)
			//os.Exit(0)
			return
		}
		fmt.Println("数据包解密后原始数据", string(ret))
	}

	fmt.Println("FSM next state", client.FSM.Current())
}

func newFSM() *gofsm.FSM {
	return gofsm.NewFSM(
		"LOW_START",
		gofsm.Events{
			{Name: "E_LOW_P0", Src: []string{"LOW_START"}, Dst: "LOW_P1"},
			{Name: "E_LOW_P2", Src: []string{"LOW_P1"}, Dst: "LOW_P3"},
			{Name: "E_HIGH_ClientInitIV", Src: []string{"LOW_P3"}, Dst: "HIGH_InitIVExpand"},
			{Name: "E_HIGH_ClientEK", Src: []string{"HIGH_InitIVExpand"}, Dst: "HIGH_ClientInit"},
		},
		gofsm.Callbacks{},
	)
}

func sharedSecret(serverPrivateKey ed25519.PrivateKey, clientPublicKey ed25519.PublicKey, alpha, beta []byte) ([]byte, []byte, error) {
	fmt.Println("计算共享密钥IV和MAC", serverPrivateKey, clientPublicKey, alpha, beta)
	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(serverPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	point, err := new(edwards25519.Point).SetBytes(clientPublicKey)
	if err != nil {
		return nil, nil, err
	}
	sharedData := point.ScalarMult(scalar, point).Bytes()
	fmt.Println("共享密钥数据", sharedData)

	sharedIV := sha512.Sum512(sharedData[:32])

	// Xor alpha
	for i := range alpha {
		sharedIV[i] ^= alpha[i]
	}
	// Xor
	for i := range beta {
		sharedIV[10+i] ^= beta[i]
	}

	macHash := sha1.Sum(sharedIV[:])
	sharedMAC := macHash[:8]
	return sharedIV[:], sharedMAC, nil
}

func calculateKeyAndNonce(t packets.PacketType, packetId uint16, generationId uint32, direction packets.PacketDirection, sharedIV []byte) ([]byte, []byte) {
	temporary := make([]byte, 70)
	if direction == packets.PacketDirectionS2C {
		temporary[0] = 0x30
	} else {
		temporary[0] = 0x31
	}
	// packet type
	temporary[1] = uint8(t)

	// generation id
	gId := make([]byte, 4)
	binary.BigEndian.PutUint32(gId, generationId)
	for i, b := range gId {
		temporary[2+i] = b
	}

	// sharedIV
	for i, b := range sharedIV {
		temporary[6+i] = b
	}

	// calculate key and nonce
	keyNonce := sha256.Sum256(temporary)
	key := keyNonce[:16]
	nonce := keyNonce[16:32]
	key[0] ^= byte((packetId & 0xFF00) >> 8)
	key[1] ^= byte((packetId & 0x00FF) >> 0)

	return key, nonce
}
