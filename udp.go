package socks5

import (
	"fmt"
	"net"
	"strconv"
)

type AddrByte []byte

type UDPDatagram struct {
	Rsv     []byte //0x00,0x00
	Frag    byte
	AType   byte
	DstAddr []byte
	DstPort []byte
	Data    []byte
}

func (p *UDPDatagram) Address() string {
	var bAddr []byte
	bAddr = append(bAddr, p.AType)
	bAddr = append(bAddr, p.DstAddr...)
	bAddr = append(bAddr, p.DstPort...)
	return AddrByte(bAddr).String()
}

var (
	ErrAddrType     = fmt.Errorf("Unrecognized address type")
	ErrSocksVersion = fmt.Errorf("not socks version 5")
	ErrMethod       = fmt.Errorf("Unsupport method")
	ErrBadRequest   = fmt.Errorf("bad request")
	ErrUDPFrag      = fmt.Errorf("Frag !=0 not supported")
)

func NewAddrByteFromString(s string) (AddrByte, error) {
	var addr []byte

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("addr:%s SplitHostPort %v", s, err)
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, 1+net.IPv4len+2)
			addr[0] = IPv4
			copy(addr[1:], ip4)
		} else {
			addr = make([]byte, 1+net.IPv6len+2)
			addr[0] = IPv6
			copy(addr[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("host:%s too long", host)
		}

		addr = make([]byte, 1+1+len(host)+2)
		addr[0] = DomainName
		addr[1] = byte(len(host))
		copy(addr[2:], host)
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port:%s ParseUint %v", port, err)
	}

	addr[len(addr)-2], addr[len(addr)-1] = byte(portNum>>8), byte(portNum)
	return addr, nil
}

func NewUDPDatagram(addrByte AddrByte, data []byte) *UDPDatagram {
	atype, addr, port := addrByte.Split()
	return &UDPDatagram{
		Rsv:     []byte{0, 0},
		Frag:    0,
		AType:   atype,
		DstAddr: addr,
		DstPort: port,
		Data:    data,
	}
}

func (d *UDPDatagram) ToBytes() []byte {
	buf := make([]byte, 0, 3+len(d.DstAddr)+2+len(d.Data))
	buf = append(buf, d.Rsv...)
	buf = append(buf, d.Frag)
	buf = append(buf, d.AType)
	buf = append(buf, d.DstAddr...)
	buf = append(buf, d.DstPort...)
	buf = append(buf, d.Data...)
	return buf
}

func (a AddrByte) Split() (aType byte, addr []byte, port []byte) {
	aType = []byte{0}[0]
	addr = []byte{0, 0, 0, 0}
	port = []byte{0, 0}

	if a != nil {
		aType = a[0]
		addr = a[1 : len(a)-2]
		port = a[len(a)-2:]
	}
	return
}

func NewUDPDatagramFromBytes(b []byte) (*UDPDatagram, error) {
	if len(b) < 4 {
		return nil, ErrBadRequest
	}

	bAddr, err := NewAddrByteFromByte(b[3:])
	if err != nil {
		return nil, err
	}

	data := b[3+len(bAddr):]
	return NewUDPDatagram(bAddr, data), nil
}

func NewAddrByteFromByte(b []byte) (AddrByte, error) {
	if len(b) < 1 {
		return nil, ErrBadRequest
	}
	var startPos int = 1
	var addrLen int
	switch b[0] {
	case DomainName:
		if len(b) < 2 {
			return nil, ErrBadRequest
		}
		// 1 byte domain length，addrLen = second byte
		startPos++
		addrLen = int(b[1])
	case IPv4:
		addrLen = net.IPv4len
	case IPv6:
		addrLen = net.IPv6len
	default:
		return nil, ErrAddrType
	}

	endPos := startPos + addrLen + 2

	if len(b) < endPos {
		return nil, ErrBadRequest
	}
	return b[:endPos], nil
}
