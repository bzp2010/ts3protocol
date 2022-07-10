package main

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"os"

	gofsm "github.com/looplab/fsm"

	"github.com/bzp2010/ts3protocol/tsproto/packets"
)

func main() {
	fmt.Println(elliptic.P256().Params())

	return

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

var (
	fsmMap = make(map[string]*gofsm.FSM)
)

func handleClient(conn *net.UDPConn) {
	// read udp data
	data := make([]byte, 500)
	n, remoteAddr, err := conn.ReadFromUDP(data)
	if err != nil {
		fmt.Println("failed to read UDP msg because of ", err.Error())
		return
	}

	if _, ok := fsmMap[remoteAddr.String()]; !ok {
		fmt.Println("为", remoteAddr, "创建新状态机实例")
		fsmMap[remoteAddr.String()] = gofsm.NewFSM(
			"LOW_START",
			gofsm.Events{
				{Name: "E_LOW_P0", Src: []string{"LOW_START"}, Dst: "LOW_P1"},
				{Name: "E_LOW_P2", Src: []string{"LOW_P1"}, Dst: "LOW_P3"},
			},
			gofsm.Callbacks{},
		)
	}
	fsm := fsmMap[remoteAddr.String()]

	// parse C2S packet
	c2sp := &packets.C2SPacket{}
	_ = c2sp.Unmarshal(data[:n])

	if (fsm.Is("LOW_START") || fsm.Is("LOW_P1") || fsm.Is("LOW_P3")) && c2sp.MAC != "TS3INIT1" {
		//fmt.Println("状态机状态错误，忽略数据包")
		return
	}

	fmt.Println("-------------------------------")
	fmt.Println("RECEIVE", n, remoteAddr /*c2sp*/)

	switch fsm.Current() {
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
		fsm.Event("E_LOW_P0")
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
		fsm.Event("E_LOW_P2")
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
		cmd := &packets.Command{}
		err = cmd.Unmarshal(init4.Data)
		if err != nil {
			fmt.Println("接收到错误INIT4.CMD", err)
			os.Exit(0)
		}
		fmt.Println("接收到INIT4.CMD", cmd)
		omega, err := base64.StdEncoding.DecodeString(cmd.Params["omega"])
		if err != nil {
			fmt.Println("BASE64解码Omega错误", err)
			os.Exit(0)
		}

		var ooo asn1.RawValue
		_, err = asn1.Unmarshal(omega, &ooo)

		var bs asn1.BitString
		var keySize int32
		var publicKeyX *big.Int
		var publicKeyY *big.Int
		omega, err = asn1.Unmarshal(ooo.Bytes, &bs)
		if err != nil {
			fmt.Println("ASN1 Omega解码错误 bs", err)
			os.Exit(0)
		}
		fmt.Println("接收到Omega数据 bs", bs)
		omega, err = asn1.Unmarshal(omega, &keySize)
		if err != nil {
			fmt.Println("ASN1 Omega解码错误 keySize", err)
			os.Exit(0)
		}
		fmt.Println("接收到Omega数据 keySize", keySize)
		omega, err = asn1.Unmarshal(omega, &publicKeyX)
		if err != nil {
			fmt.Println("ASN1 Omega解码错误 publicKeyX", err)
			os.Exit(0)
		}
		fmt.Println("接收到Omega数据 publicKeyX", publicKeyX)
		omega, err = asn1.Unmarshal(omega, &publicKeyY)
		if err != nil {
			fmt.Println("ASN1 Omega解码错误 publicKeyY", err)
			os.Exit(0)
		}
		fmt.Println("接收到Omega数据 publicKeyY", publicKeyY, "剩余数据", omega)

		type ellipticPublicKey struct {
			elliptic.Curve
			X, Y *big.Int
		}

		/*curve := elliptic.P256()
		data := elliptic.Marshal(curve, publicKeyX, publicKeyY)
		elliptic.GenerateKey(curve, bytes.NewReader(data))
		fmt.Println(elliptic.GenerateKey(elliptic.P256(), bytes.NewReader(data)))

		pubkeyCurve := elliptic.P256()*/
		//os.Exit(0)
	}

	fmt.Println("FSM next state", fsm.Current())
}
