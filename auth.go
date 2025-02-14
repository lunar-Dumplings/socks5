package socks5

import (
	"io"
	"net"
	"errors"
)
const (
	SOCKS5Version = 0x05
	ReservedFeild = 0x00
)

const (
	NoAuth          = 0x00
	GSSAPI          = 0x01
	NoAcceptable    = 0xff
	UserPassword    = 0x02
)

var ErrVersion = errors.New("invalid version")
var ErrInvalidMethod = errors.New("invalid method")
var ErrInvaildReservedField = errors.New("invalid reserved field")
var ErrInvalidAddressType = errors.New("invalid address type")
var ErrInvalidPort = errors.New("invalid port")
var ErrUnsupportedCommand = errors.New("unsupported command")

type Method = byte


type ClientAuthMassage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

func NewClientAuthMassage(conn net.Conn) (*ClientAuthMassage, error) {
	//读取版本和方法数
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	if buf[0] != SOCKS5Version {
		return nil, ErrVersion
	}
	//读取方法
	nMethods := buf[1]
	buf = make([]byte, nMethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return &ClientAuthMassage{
		Version: SOCKS5Version,
		NMethods: nMethods,
		Methods: buf,
	}, nil
}

func NewServerAuthMassage(conn net.Conn, method Method) error {
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	return err
}
