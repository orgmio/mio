package protocol

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

// TunnelKind 标识最终胜出的传输层类型，供上层日志/统计使用。
type TunnelKind int

const (
	TunnelUnknown TunnelKind = iota
	TunnelTCP                // TLS over TCP（HTTP/1.1 或 H2 ALPN，取决于协商结果）
	TunnelQUIC               // HTTP/3 over QUIC
)

func (k TunnelKind) String() string {
	switch k {
	case TunnelTCP:
		return "tcp+tls"
	case TunnelQUIC:
		return "quic"
	default:
		return "unknown"
	}
}

// Tunnel 是连接建立完成后暴露给上层（SOCKS5 转发逻辑）使用的统一接口。
type Tunnel interface {
	// Stream 返回一个可用于双向读写业务数据的 net.Conn。
	Stream() net.Conn
	Kind() TunnelKind
	Close() error
}

// DialOptions 汇总建立连接所需的全部参数，直接来自配置文件的 [peer] 段。
type DialOptions struct {
	ServerAddr  string        // peer.server
	Port        int           // peer.port（TCP 443 与 UDP 443 共用这个端口号）
	SNI         string        // peer.sni，写入 ClientHello 的 server_name 扩展
	Key         []byte        // 解码后的共享密钥
	DialTimeout time.Duration // 单条路径的连接超时，建议 5~8 秒
}

// raceResult 用于在 goroutine 之间传递单条路径的建连结果。
type raceResult struct {
	kind   TunnelKind
	tunnel Tunnel
	err    error
}

// Dial 并行发起 TCP+TLS 与 QUIC 两条路径，返回率先完成"传输层连接 + 认证帧发送"
// 全过程的那一条。落败的一方会被异步清理（不阻塞返回）。
func Dial(ctx context.Context, opts DialOptions) (Tunnel, error) {
	if len(opts.Key) == 0 {
		return nil, errors.New("ixa: empty key")
	}

	resultCh := make(chan raceResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		t, err := dialTCP(ctx, opts)
		resultCh <- raceResult{kind: TunnelTCP, tunnel: t, err: err}
	}()

	go func() {
		defer wg.Done()
		t, err := dialQUIC(ctx, opts)
		resultCh <- raceResult{kind: TunnelQUIC, tunnel: t, err: err}
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var firstErr error
	gotFirst := false

	for res := range resultCh {
		if res.err == nil {
			if !gotFirst {
				gotFirst = true
				winner := res
				go drainAndLingerLoser(resultCh)
				return winner.tunnel, nil
			}
			// 已经有胜出者，这是较晚到达的第二个成功结果，
			// 交给 drainAndLingerLoser 处理，这里不重复处理。
			continue
		}
		if firstErr == nil {
			firstErr = res.err
		}
	}

	if firstErr == nil {
		firstErr = errors.New("ixa: both tcp and quic dial paths failed with no specific error")
	}
	return nil, fmt.Errorf("ixa: all dial paths failed: %w", firstErr)
}

// drainAndLingerLoser 消费 race 中较晚到达的那个结果。
// 若它其实也成功建立了连接，按照"模拟真实浏览器不会突兀断开次要连接"的原则，
// 保留几秒后再关闭，而不是立刻 Close。
func drainAndLingerLoser(resultCh <-chan raceResult) {
	res, ok := <-resultCh
	if !ok || res.err != nil || res.tunnel == nil {
		return
	}
	time.Sleep(3 * time.Second)
	_ = res.tunnel.Close()
}

// ---------------------------------------------------------------------------
// TCP + uTLS 路径
// ---------------------------------------------------------------------------

type tcpTunnel struct {
	conn *utls.UConn
}

func (t *tcpTunnel) Stream() net.Conn { return t.conn }
func (t *tcpTunnel) Kind() TunnelKind { return TunnelTCP }
func (t *tcpTunnel) Close() error     { return t.conn.Close() }

func dialTCP(ctx context.Context, opts DialOptions) (Tunnel, error) {
	addr := net.JoinHostPort(opts.ServerAddr, strconv.Itoa(opts.Port))

	dialer := &net.Dialer{Timeout: opts.DialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	uConn, err := handshakeWithEmbeddedAuth(rawConn, opts)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	if err := sendAuthFrame(uConn, opts.Key); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("send auth frame over tcp: %w", err)
	}

	return &tcpTunnel{conn: uConn}, nil
}

// handshakeWithEmbeddedAuth 用 uTLS 的 Chrome 指纹预设完成 TLS 握手，
// 并在握手发起前将 HMAC 认证信息写入 ClientHello.Random。
func handshakeWithEmbeddedAuth(rawConn net.Conn, opts DialOptions) (*utls.UConn, error) {
	tlsConfig := &utls.Config{
		ServerName: opts.SNI,
	}

	uConn := utls.UClient(rawConn, tlsConfig, utls.HelloChrome_Auto)

	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("utls build handshake state: %w", err)
	}

	embeddedRandom := GenerateClientRandom(opts.Key, time.Now().Unix())
	if uConn.HandshakeState.Hello == nil {
		return nil, errors.New("utls handshake state has no ClientHello to patch")
	}
	copy(uConn.HandshakeState.Hello.Random[:], embeddedRandom[:])

	// 关键：重新 marshal，否则上面对 Random 的修改不会体现在实际发送的字节里。
	if err := uConn.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("utls marshal client hello after patching random: %w", err)
	}

	if err := uConn.Handshake(); err != nil {
		return nil, fmt.Errorf("utls handshake: %w", err)
	}
	return uConn, nil
}

func overwriteClientHelloRandom(uConn *utls.UConn, random [32]byte) error {
	hs := uConn.HandshakeState
	if hs.Hello == nil {
		return errors.New("utls handshake state has no ClientHello to patch")
	}
	copy(hs.Hello.Random[:], random[:])
	uConn.HandshakeState = hs
	return nil
}

// sendAuthFrame 在已建立的加密隧道上发送应用层认证帧。
func sendAuthFrame(conn net.Conn, key []byte) error {
	frame := BuildAuthFrame(key, time.Now())
	_, err := conn.Write(frame)
	return err
}

// ---------------------------------------------------------------------------
// QUIC 路径
// ---------------------------------------------------------------------------

type quicTunnel struct {
	connection *quic.Conn
	stream     *quic.Stream
}

func (t *quicTunnel) Stream() net.Conn { return quicStreamConn{t.stream, t.connection} }
func (t *quicTunnel) Kind() TunnelKind { return TunnelQUIC }
func (t *quicTunnel) Close() error     { return t.connection.CloseWithError(0, "") }

func dialQUIC(ctx context.Context, opts DialOptions) (Tunnel, error) {
	addr := net.JoinHostPort(opts.ServerAddr, strconv.Itoa(opts.Port))

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve quic udp addr: %w", err)
	}

	// TODO(下一版): quic-go 目前不像 uTLS 那样支持细粒度定制 ClientHello 字节，
	// 因此 QUIC 路径的 Random 字段暂时无法嵌入 HMAC，只能在握手完成后
	// 用应用层认证帧兜底。需要调研 quic-go 是否已支持自定义底层 Random 生成器
	// 或通过 GetConfigForClient + 自定义 rand.Reader 注入的方式补上这块。
	tlsConfig := &tls.Config{
		ServerName: opts.SNI,
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}

	quicConf := &quic.Config{
		HandshakeIdleTimeout: opts.DialTimeout,
	}

	dialCtx, cancel := context.WithTimeout(ctx, opts.DialTimeout)
	defer cancel()

	conn, err := quic.DialAddr(dialCtx, udpAddr.String(), tlsConfig, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	stream, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		conn.CloseWithError(0, "open stream failed")
		return nil, fmt.Errorf("quic open stream: %w", err)
	}

	tunnel := &quicTunnel{connection: conn, stream: stream}
	if err := sendAuthFrame(tunnel.Stream(), opts.Key); err != nil {
		tunnel.Close()
		return nil, fmt.Errorf("send auth frame over quic: %w", err)
	}

	return tunnel, nil
}

type quicStreamConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (c quicStreamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c quicStreamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
