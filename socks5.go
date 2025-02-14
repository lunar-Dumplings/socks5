package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

type Server interface {
	Run() error
}

type SOCKS5Server struct {
	IP   string
	Port int
}
type SenderMap struct {
	sync.Map
}

const MaxSegmentSize = 65535

const UDPprot = 1080

var senders SenderMap
var client SenderMap

func (p *SenderMap) Get(key string) (net.PacketConn, bool) {
	v, exist := p.Load(key)
	if !exist {
		return nil, false
	}

	return v.(net.PacketConn), true
}

func (p *SenderMap) Del(key string) net.PacketConn {
	if conn, exist := p.Get(key); exist {
		p.Map.Delete(key)
		return conn
	}

	return nil
}

func (s *SOCKS5Server) Run() error {
	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("连接出现错误，地址为%s,%s", conn.RemoteAddr(), err)
			continue
		}

		go func() {
			defer conn.Close()
			err := handleConnection(conn)
			if err != nil {
				log.Printf("处理错误，地址为%s,%s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConnection(conn net.Conn) error {
	//协商
	if err := auth(conn); err != nil {
		return err
	}
	//请求
	err := request(conn)
	if err != nil {
		return err
	}
	return nil
}

func auth(conn net.Conn) error {
	clientMessage, err := NewClientAuthMassage(conn)
	if err != nil {
		return err
	}
	log.Printf("客户端消息：%v", clientMessage)
	var acc bool
	for _, method := range clientMessage.Methods {
		if method == NoAuth {
			acc = true
			break
		}
	}
	if !acc {
		NewServerAuthMassage(conn, NoAcceptable)
		return errors.New("没有合适的方法")
	}
	return NewServerAuthMassage(conn, NoAuth)
}

func request(conn net.Conn) error {
	clientMessage, err := NewClientRequestMassage(conn)
	if err != nil {
		return err
	}
	if clientMessage.Cmd == Bind {
		return SendReply(conn, commandNotSupported, nil)
	}
	if clientMessage.Cmd == UDPAssociate {
		return handleUDPAssociate(conn, clientMessage)
	}
	if clientMessage.AddrType == IPv6 {
		return SendReply(conn, addrTypeNotSupported, nil)
	}
	return handleTCPRequest(conn, clientMessage)
}

func handleTCPRequest(conn net.Conn, clientMessage *ClientRequestMassage) error {
	//请求访问目标TCP服务
	address := fmt.Sprintf("%s:%d", clientMessage.Address, clientMessage.Port)
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}

		return SendReply(conn, resp, nil)
	}
	//发送成功报文
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.TCPAddr)
	addrSpec := &AddrSpec{
		IP:   addr.IP,
		Port: addr.Port,
	}
	err = SendReply(conn, successReply, addrSpec)
	if err != nil {
		return err
	}
	return tcpForward(conn, targetConn)
}

func handleUDPAssociate(conn net.Conn, clientMessage *ClientRequestMassage) error {
	addrSpec := &AddrSpec{
		Port: UDPprot,
	}
	err := SendReply(conn, successReply, addrSpec)
	if err != nil {
		return err
	}
	//将客户端地址储存起来
	clientAddr := conn.RemoteAddr().String()
	client.Store(conn, clientAddr)
	//接收转发客户端的UDP数据包
	go udpForward(addrSpec)
	return nil
}

func udpForward(addrSpec *AddrSpec) {
	listenAddr := &net.UDPAddr{
		IP:   addrSpec.IP,
		Port: addrSpec.Port,
	}
	relayer, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return
	}
	for {
		buf := make([]byte, MaxSegmentSize)

		n, addr, err := relayer.ReadFrom(buf)
		if err != nil {
			continue
		}
		saddr := addr.String()
		_, exist := client.Get(saddr)
		if !exist {
			//无视没有协商的客户端
			continue
		}
		sender, exist := senders.Get(saddr)
		if !exist {
			sender, err = net.ListenPacket("udp", "")
			if err != nil {
				continue
			}
			senders.Store(addr.String(), sender)

			go func() {
				relayToClient(sender, relayer, addr)
				if sender := senders.Del(saddr); sender != nil {
					sender.Close()
				}
			}()
		}

		err = relayToRemote(sender, buf[0:n])
		if err != nil {
			continue
		}
	}
}

func relayToClient(receiver net.PacketConn, relayer net.PacketConn, clientAddr net.Addr) error {
	buf := make([]byte, MaxSegmentSize)

	for {
		n, addr, err := receiver.ReadFrom(buf)
		if err != nil {
			return err
		}

		bAddr, err := NewAddrByteFromString(addr.String())
		if err != nil {
			return err
		}

		_, err = relayer.WriteTo(NewUDPDatagram(bAddr, buf[:n]).ToBytes(), clientAddr)
		if err != nil {
			return err
		}
	}
}

func relayToRemote(sender net.PacketConn, datagram []byte) error {
	d, err := NewUDPDatagramFromBytes(datagram)
	if err != nil {
		return err
	}
	if d.Frag != 0x00 { //不支持udp分片
		return ErrUDPFrag
	}

	udpTargetAddr := d.Address()

	tgtUDPAddr, err := net.ResolveUDPAddr("udp", udpTargetAddr)
	if err != nil {
		return err
	}

	logrus.Debug("udp req:", udpTargetAddr)

	_, err = sender.WriteTo(d.Data, tgtUDPAddr)
	return err
}

func parseFrame(buffer []byte, atyp byte) (net.IP, uint16, []byte, error) {
	var dstAddr net.IP
	var dstPort uint16
	var data []byte

	switch atyp {
	case 0x01: // IPv4
		if len(buffer) < 7 {
			return nil, 0, nil, fmt.Errorf("无效的IPv4帧长度")
		}
		dstAddr = net.IPv4(buffer[0], buffer[1], buffer[2], buffer[3])
		dstPort = binary.BigEndian.Uint16(buffer[4:6])
		data = buffer[6:]
	case 0x03: // 域名
		domainLen := int(buffer[0])
		if len(buffer) < 2+domainLen+2 {
			return nil, 0, nil, fmt.Errorf("无效的域名帧长度")
		}
		dstAddr = net.IP(buffer[1 : 1+domainLen])
		dstPort = binary.BigEndian.Uint16(buffer[1+domainLen : 1+domainLen+2])
		data = buffer[1+domainLen+2:]
	case 0x04: // IPv6
		if len(buffer) < 19 {
			return nil, 0, nil, fmt.Errorf("无效的IPv6帧长度")
		}
		dstAddr = net.IP(buffer[0:16])
		dstPort = binary.BigEndian.Uint16(buffer[16:18])
		data = buffer[18:]
	default:
		return nil, 0, nil, fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	return dstAddr, dstPort, data, nil
}

func buildFrame(dstAddr net.IP, dstPort uint16, data []byte) []byte {
	var frame []byte
	frame = append(frame, 0x00, 0x00) // RSV
	frame = append(frame, 0x00)       // FRAG

	if dstAddr.To4() != nil {
		frame = append(frame, 0x01) // ATYP (IPv4)
		frame = append(frame, dstAddr.To4()...)
	} else if dstAddr.To16() != nil {
		frame = append(frame, 0x04) // ATYP (IPv6)
		frame = append(frame, dstAddr.To16()...)
	} else {
		// 不支持的地址类型
		return nil
	}

	frame = append(frame, byte(dstPort>>8), byte(dstPort&0xff)) // DST.PORT
	frame = append(frame, data...)                              // DATA

	return frame
}

func tcpForward(conn net.Conn, targetConn net.Conn) error {
	defer targetConn.Close()
	go io.Copy(targetConn, conn)
	_, err := io.Copy(conn, targetConn)
	return err
}
