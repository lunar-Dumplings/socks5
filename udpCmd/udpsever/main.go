package main

import (
	"log"
	"net"
)

func main() {
	addr := net.UDPAddr{
		Port: 9999, // 你可以选择任何未被占用的端口
		IP:   net.ParseIP("127.0.0.1"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("无法启动UDP服务器: %v", err)
	}
	defer conn.Close()

	log.Printf("UDP服务器已启动，监听端口 %d", addr.Port)

	buffer := make([]byte, 1024)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("读取UDP数据包错误: %v", err)
			continue
		}

		log.Printf("接收到来自 %v 的数据: %s", clientAddr, string(buffer[:n]))

		// 发送响应
		response := []byte("Hello from UDP server")
		_, err = conn.WriteToUDP(response, clientAddr)
		if err != nil {
			log.Printf("发送响应错误: %v", err)
			continue
		}

		log.Printf("已发送响应到 %v", clientAddr)
	}
}
