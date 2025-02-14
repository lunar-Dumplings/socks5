package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type AddrSpec struct {
	IP   net.IP
	FQDN string
	Port int
}

const (
	IPV4Len = 4
	IPV6Len = 16
)

type ClientRequestMassage struct {
	Cmd      Command
	AddrType AddressType
	Address  string
	Port     uint16
}

type Command = byte

const (
	Connect      Command = 0x01
	Bind         Command = 0x02
	UDPAssociate Command = 0x03
)

type AddressType = byte

const (
	IPv4       AddressType = 0x01
	DomainName AddressType = 0x03
	IPv6       AddressType = 0x04
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

func NewClientRequestMassage(conn net.Conn) (*ClientRequestMassage, error) {
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	//检查
	version, command, reserved, addrType := buf[0], buf[1], buf[2], buf[3]
	if version != SOCKS5Version {
		return nil, ErrVersion
	}
	if command != Connect && command != Bind && command != UDPAssociate {
		return nil, ErrUnsupportedCommand
	}
	if reserved != ReservedFeild {
		return nil, ErrInvaildReservedField
	}
	if addrType != IPv4 && addrType != DomainName && addrType != IPv6 {
		return nil, ErrInvalidAddressType
	}
	//读取地址和端口
	var address string
	switch addrType {
	case IPv4:
		buf = make([]byte, IPV4Len)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return nil, err
		}
		address = net.IP(buf[0:4]).String()
	case DomainName:
		buf = make([]byte, 1)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return nil, err
		}
		buf = make([]byte, buf[0])
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return nil, err
		}
		address = string(buf)
	case IPv6:
		buf = make([]byte, IPV6Len)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return nil, err
		}
		address = net.IP(buf[0:16]).String()
	}
	buf = make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(buf[len(buf)-2:])
	//if port == 0 {
	//	return nil, ErrInvalidPort
	//}
	fmt.Printf("address: %s, port: %d\n", address, port)
	return &ClientRequestMassage{
		Cmd:     command,
		Address: address,
		Port:    port,
	}, nil
}

func SendReply(conn net.Conn, rep uint8, addr *AddrSpec) error {
	reply := []byte{SOCKS5Version, rep, ReservedFeild}
	if addr == nil {
		addr = &AddrSpec{}
	}
	switch {
	case addr.IP.To4() != nil:
		// IPv4 地址
		reply = append(reply, IPv4)
		reply = append(reply, addr.IP.To4()...)
	case addr.FQDN != "":
		// 域名地址
		reply = append(reply, DomainName)
		reply = append(reply, byte(len(addr.FQDN)))
		reply = append(reply, []byte(addr.FQDN)...)
	case addr.IP.To16() != nil:
		// IPv6 地址
		reply = append(reply, IPv6)
		reply = append(reply, addr.IP.To16()...)
	case addr.IP == nil:
		// 无地址
		reply = append(reply, IPv4)
		reply = append(reply, []byte{0, 0, 0, 0}...)
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(addr.Port))
	reply = append(reply, port...)
	_, err := conn.Write(reply)
	return err
}
