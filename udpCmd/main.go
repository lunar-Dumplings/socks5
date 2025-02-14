package main

import (
	"fmt"
	"log"
	"net"
)

const (
	socks5Version   = 0x05
	noAuth          = 0x00
	udpAssociateCmd = 0x03
)

func main() {
	serverAddr := "127.0.0.1:1080" // 替换为你的 SOCKS5 服务器地址
	targetAddr := "127.0.0.1:9999" // 替换为你的 UDP 服务器地址

	//建立与 SOCKS5 服务器的 TCP 连接
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("无法连接到 SOCKS5 服务器: %v", err)
	}
	defer conn.Close()

	// 进行身份验证
	if err := authenticate(conn); err != nil {
		log.Fatalf("身份验证失败: %v", err)
	}

	// 发送 UDP ASSOCIATE 请求
	udpConn, serverUDPAddr, err := udpAssociate(conn, targetAddr)
	if err != nil {
		log.Fatalf("UDP ASSOCIATE 请求失败: %v", err)
	}
	defer udpConn.Close()

	// 发送 UDP 数据包
	if err := sendUDPRequest(udpConn, serverUDPAddr, targetAddr); err != nil {
		log.Fatalf("发送 UDP 请求失败: %v", err)
	}

	// 接收 UDP 响应
	if err := receiveUDPResponse(udpConn); err != nil {
		log.Fatalf("接收 UDP 响应失败: %v", err)
	}
}

func authenticate(conn net.Conn) error {
	// 发送认证方法选择消息
	_, err := conn.Write([]byte{socks5Version, 1, noAuth})
	if err != nil {
		return err
	}

	// 接收服务器响应
	resp := make([]byte, 2)
	_, err = conn.Read(resp)
	if err != nil {
		return err
	}

	if resp[1] != noAuth {
		return fmt.Errorf("服务器不接受无认证方法")
	}

	return nil
}

func udpAssociate(conn net.Conn, targetAddr string) (*net.UDPConn, *net.UDPAddr, error) {
	// 创建 UDP 连接
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, err
	}

	// 解析目标地址
	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		udpConn.Close()
		return nil, nil, err
	}
	targetUDPAddr.IP = net.IPv4(127, 0, 0, 1)
	// 发送 UDP ASSOCIATE 请求
	// request := []byte{
	// 	socks5Version, udpAssociateCmd, 0, 1, // VER, CMD, RSV, ATYP (IPv4)
	// 	127, targetUDPAddr.IP[1], targetUDPAddr.IP[2], 1, // DST.ADDR (IPv4 address)
	// 	byte(targetUDPAddr.Port >> 8), byte(targetUDPAddr.Port & 0xff), // DST.PORT
	// }
	// _, err = conn.Write(request)
	// if err != nil {
	// 	udpConn.Close()
	// 	return nil, nil, err
	// }

	// 接收服务器响应
	// resp := make([]byte, 10)
	// _, err = conn.Read(resp)
	// if err != nil {
	// 	udpConn.Close()
	// 	return nil, nil, err
	// }

	// if resp[1] != 0x00 {
	// 	udpConn.Close()
	// 	return nil, nil, fmt.Errorf("UDP ASSOCIATE 请求失败")
	// }

	// 获取服务器的 UDP 绑定地址
	serverUDPAddr := &net.UDPAddr{
		//IP:   net.IPv4(resp[4], resp[5], resp[6], resp[7]),
		IP:   net.IPv4(127, 0, 0, 1),
		//Port: int(resp[8])<<8 | int(resp[9]),
		Port: 1080,
	}

	return udpConn, serverUDPAddr, nil
}

func sendUDPRequest(udpConn *net.UDPConn, serverUDPAddr *net.UDPAddr, targetAddr string) error {
	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return err
	}

	// 构建 UDP 数据包
	data := []byte("Hello, UDP!")
	packet := make([]byte, 10+len(data))
	packet[0] = 0x00 // RSV
	packet[1] = 0x00 // RSV
	packet[2] = 0x00 // FRAG
	packet[3] = 0x01 // ATYP (IPv4)
	copy(packet[4:8], targetUDPAddr.IP.To4())
	packet[8] = byte(targetUDPAddr.Port >> 8)
	packet[9] = byte(targetUDPAddr.Port & 0xff)
	copy(packet[10:], data)

	// 发送 UDP 数据包
	_, err = udpConn.WriteToUDP(packet, serverUDPAddr)
	return err
}

func receiveUDPResponse(udpConn *net.UDPConn) error {
	buffer := make([]byte, 65535)
	//udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, addr, err := udpConn.ReadFromUDP(buffer)
	if err != nil {
		return err
	}

	log.Printf("接收到来自 %v 的 UDP 响应: %s", addr, string(buffer[10:n]))
	return nil
}
