package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"ixa-go/protocol"
)

func main() {
	configPath := flag.String("c", "", "Config file path")
	flag.Parse()

	if *configPath == "" {
		fmt.Println("Usage: ixa -c config_file_path")
		os.Exit(1)
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Printf("load config: %v\n", err)
		os.Exit(1)
	}

	if !cfg.HasPeer() && !cfg.HasServer() {
		fmt.Println("config must have at least one of [peer] or [server] filled in")
		os.Exit(1)
	}

	// 本次交付：仅实现 [peer] 客户端角色的连接建立验证。
	// [server] 角色（TCP Peek 判断 + 真假分流）留待下一版实现。
	if cfg.HasPeer() {
		runPeer(cfg.Peer)
	}

	if cfg.HasServer() {
		fmt.Println("[server] role is configured but not yet implemented in this build")
	}
}

func runPeer(peerCfg PeerConfig) {
	key, err := peerCfg.PeerKey()
	if err != nil {
		fmt.Printf("invalid [peer] config: %v\n", err)
		os.Exit(1)
	}
	if peerCfg.Server == "" || peerCfg.SNI == "" {
		fmt.Println("peer.server and peer.sni must not be empty")
		os.Exit(1)
	}

	opts := protocol.DialOptions{
		ServerAddr:  peerCfg.Server,
		Port:        peerCfg.Port,
		SNI:         peerCfg.SNI,
		Key:         key,
		DialTimeout: 8 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := time.Now()
	tunnel, err := protocol.Dial(ctx, opts)
	if err != nil {
		reportDialFailed(time.Since(start), err)
		os.Exit(1)
	}
	defer tunnel.Close()

	reportTunnelEstablished(tunnel.Kind(), time.Since(start))

	// 本次交付到此为止：暂不接 SOCKS5 数据转发，先保持连接几秒钟方便抓包观察。
	time.Sleep(3 * time.Second)
}

// reportTunnelEstablished 打印一次连接建立成功的摘要信息。
func reportTunnelEstablished(kind protocol.TunnelKind, elapsed time.Duration) {
	fmt.Printf("tunnel established via %s in %s\n", kind, elapsed)
	fmt.Println("auth frame sent successfully, connection is authenticated.")
}

// reportDialFailed 打印一次连接建立失败的摘要信息。
func reportDialFailed(elapsed time.Duration, err error) {
	fmt.Printf("dial failed after %s: %v\n", elapsed, err)
}
