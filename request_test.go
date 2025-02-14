package socks5

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func TestNewClientRequestMassage(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "Valid IPv4 Connect",
			input:   []byte{0x05, 0x01, 0x00, 0x01, 192, 168, 0, 1, 0x1F, 0x90},
			wantErr: false,
		},
		{
			name:    "Invalid Version",
			input:   []byte{0x04, 0x01, 0x00, 0x01, 192, 168, 0, 1, 0x1F, 0x90},
			wantErr: true,
		},
		{
			name:    "Unsupported Command",
			input:   []byte{0x05, 0x04, 0x00, 0x01, 192, 168, 0, 1, 0x1F, 0x90},
			wantErr: true,
		},
		{
			name:    "Invalid Reserved Field",
			input:   []byte{0x05, 0x01, 0x01, 0x01, 192, 168, 0, 1, 0x1F, 0x90},
			wantErr: true,
		},
		{
			name:    "Invalid Address Type",
			input:   []byte{0x05, 0x01, 0x00, 0x05, 192, 168, 0, 1, 0x1F, 0x90},
			wantErr: true,
		},
		{
			name:    "Valid Domain Name",
			input:   []byte{0x05, 0x01, 0x00, 0x03, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x1F, 0x90},
			wantErr: false,
		},
		{
			name:    "Valid IPv6",
			input:   []byte{0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x34, 0x1F, 0x90},
			wantErr: false,
		},
		{
			name:    "Valid Port",
			input:   []byte{0x05, 0x01, 0x00, 0x01, 192, 168, 0, 1, 0x1F, 0x90},
			wantErr: false,
		},
		{
			name:    "Invalid Port",
			input:   []byte{0x05, 0x01, 0x00, 0x01, 192, 168, 0, 1, 0x1F},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{buf: bytes.NewBuffer(tt.input)}
			_, err := NewClientRequestMassage(conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClientRequestMassage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

var netDial func(network, address string) (net.Conn, error)

func TestRequest(t *testing.T) {
    tests := []struct {
        name       string
        clientMsg  []byte
        wantReply  []byte
        wantErr    bool
        dialErr    error
    }{
        {
            name: "Command not supported",
            clientMsg: []byte{SOCKS5Version, Bind, 0x00, IPv4, 127, 0, 0, 1, 0x1F, 0x90},
            wantReply: []byte{SOCKS5Version, commandNotSupported, 0x00, IPv4, 0, 0, 0, 0, 0, 0},
            wantErr:   true,
        },
        {
            name: "Address type not supported",
            clientMsg: []byte{SOCKS5Version, Bind, 0x00, IPv6, 0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x34, 0x1F, 0x90},
            wantReply: []byte{SOCKS5Version, addrTypeNotSupported, 0x00, IPv4, 0, 0, 0, 0, 0, 0},
            wantErr:   true,
        },
        {
            name: "Host unreachable",
            clientMsg: []byte{SOCKS5Version, Bind, 0x00, IPv4, 127, 0, 0, 1, 0x1F, 0x90},
            wantReply: []byte{SOCKS5Version, hostUnreachable, 0x00, IPv4, 0, 0, 0, 0, 0, 0},
            wantErr:   true,
            dialErr:   &net.OpError{Op: "dial", Err: errors.New("host unreachable")},
        },
        {
            name: "Success",
            clientMsg: []byte{SOCKS5Version, Bind, 0x00, IPv4, 127, 0, 0, 1, 0x1F, 0x90},
            wantReply: []byte{SOCKS5Version, successReply, 0x00, IPv4, 127, 0, 0, 1, 0x04, 0x38},
            wantErr:   false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            conn := &mockConn{buf: bytes.NewBuffer(tt.clientMsg)}
            dialer := func(network, address string) (net.Conn, error) {
                if tt.dialErr != nil {
                    return nil, tt.dialErr
                }
                return &mockConn{buf: new(bytes.Buffer)}, nil
            }

            // Replace net.Dial with our mock dialer
            netDial = dialer

            err := request(conn)
            if (err != nil) != tt.wantErr {
                t.Errorf("request() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got := conn.buf.Bytes(); !bytes.Equal(got, tt.wantReply) {
                t.Errorf("request() = %v, want %v", got, tt.wantReply)
            }
        })
    }
}