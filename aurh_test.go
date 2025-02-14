package socks5

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type mockConn struct {
    net.Conn
    buf *bytes.Buffer
}

func (m *mockConn) Read(b []byte) (int, error) {
    return m.buf.Read(b)
}

func (m *mockConn) Write(b []byte) (int, error) {
    return m.buf.Write(b)
}

func (m *mockConn) Close() error {
    return nil
}

func (m *mockConn) LocalAddr() net.Addr {
    return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}

func (m *mockConn) RemoteAddr() net.Addr {
    return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}

func (m *mockConn) SetDeadline(t time.Time) error {
    return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
    return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
    return nil
}

func TestNewClientAuthMassage(t *testing.T) {
    data := []byte{SOCKS5Version, 1, 0x00} // Version 5, 1 method, method 0x00
    conn := &mockConn{buf: bytes.NewBuffer(data)}

    authMsg, err := NewClientAuthMassage(conn)
    if err != nil {
        t.Fatalf("expected no error, got %v", err)
    }

    if authMsg.Version != SOCKS5Version {
        t.Errorf("expected version %v, got %v", SOCKS5Version, authMsg.Version)
    }

    if authMsg.NMethods != 1 {
        t.Errorf("expected 1 method, got %v", authMsg.NMethods)
    }

    if len(authMsg.Methods) != 1 || authMsg.Methods[0] != 0x00 {
        t.Errorf("expected method 0x00, got %v", authMsg.Methods)
    }
}