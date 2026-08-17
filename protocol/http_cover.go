package mio

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	coverHTTP2ALPN = "h2"
	coverHTTP1ALPN = "http/1.1"
)

type prefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type onceListener struct {
	addr net.Addr
	ch   chan net.Conn
	once sync.Once
}

func newOnceListener(conn net.Conn) *onceListener {
	ch := make(chan net.Conn, 1)
	ch <- conn
	return &onceListener{addr: conn.LocalAddr(), ch: ch}
}

func (l *onceListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	l.once.Do(func() { close(l.ch) })
	return conn, nil
}

func (l *onceListener) Close() error {
	l.once.Do(func() { close(l.ch) })
	return nil
}

func (l *onceListener) Addr() net.Addr { return l.addr }

func (s *TunnelServer) altSvc() string {
	port := s.config.Port
	if port <= 0 {
		port = 443
	}
	return fmt.Sprintf(`h3=":%d"; ma=2592000`, port)
}

func (s *TunnelServer) advertiseH3(header http.Header) {
	if header.Get("Alt-Svc") == "" {
		header.Set("Alt-Svc", s.altSvc())
	}
}

func (s *TunnelServer) serveAuthedTLS(ctx context.Context, conn *tls.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(tunnelDialTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	if conn.ConnectionState().NegotiatedProtocol == coverHTTP2ALPN {
		return s.serveHTTP2(ctx, conn)
	}
	return s.serveHTTP1(ctx, conn)
}

func (s *TunnelServer) serveHTTP2(ctx context.Context, conn net.Conn) error {
	server := &http2.Server{
		IdleTimeout:               30 * time.Second,
		MaxConcurrentStreams:      100,
		MaxDecoderHeaderTableSize: 65536,
		ReadIdleTimeout:           30 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	server.ServeConn(conn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: http.HandlerFunc(s.handleCoverHTTP),
	})
	close(done)
	return nil
}

func (s *TunnelServer) serveHTTP1(ctx context.Context, conn net.Conn) error {
	buffered := bufio.NewReader(conn)
	peek, err := buffered.Peek(len(tunnelMagic))
	if err == nil && string(peek) == tunnelMagic {
		return s.handle(ctx, &prefixConn{Conn: conn, reader: buffered})
	}
	request, err := http.ReadRequest(buffered)
	if err != nil {
		return err
	}
	if request.Method == http.MethodConnect {
		token, ok := parseH3Token(request.Header.Get("Proxy-Authorization"), s.key)
		if !ok {
			_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
			return errors.New("HTTP/1.1 CONNECT authentication failed")
		}
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\nAlt-Svc: %s\r\n\r\n", s.altSvc())
		return s.handle(ctx, &prefixConn{
			Conn:   conn,
			reader: io.MultiReader(bytes.NewReader(token), buffered),
		})
	}
	server := &http.Server{
		Handler:           http.HandlerFunc(s.handleCoverHTTP),
		ReadHeaderTimeout: tunnelDialTimeout,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	replay := io.MultiReader(requestPrefix(request), buffered)
	err = server.Serve(newOnceListener(&prefixConn{Conn: conn, reader: replay}))
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func requestPrefix(request *http.Request) io.Reader {
	var buf bytes.Buffer
	_ = request.Write(&buf)
	return &buf
}

func (s *TunnelServer) handleCoverHTTP(w http.ResponseWriter, request *http.Request) {
	token, ok := parseH3Token(request.Header.Get("Proxy-Authorization"), s.key)
	if request.Method != http.MethodConnect || !ok {
		s.advertiseH3(w.Header())
		s.h3Proxy().ServeHTTP(w, request)
		return
	}
	if request.ProtoMajor >= 2 {
		s.advertiseH3(w.Header())
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		conn := &httpCoverConn{
			reader:  io.MultiReader(bytes.NewReader(token), request.Body),
			writer:  w,
			request: request,
		}
		defer request.Body.Close()
		if err := s.handle(request.Context(), conn); err != nil && request.Context().Err() == nil {
			log.Printf("mio HTTP/%d CONNECT %s: %v", request.ProtoMajor, request.RemoteAddr, err)
		}
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT hijack unsupported", http.StatusInternalServerError)
		return
	}
	raw, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer raw.Close()
	_, _ = fmt.Fprintf(raw, "HTTP/1.1 200 Connection Established\r\nAlt-Svc: %s\r\n\r\n", s.altSvc())
	var leftover io.Reader = raw
	if buf != nil {
		leftover = io.MultiReader(buf, raw)
	}
	conn := &prefixConn{Conn: raw, reader: io.MultiReader(bytes.NewReader(token), leftover)}
	if err := s.handle(request.Context(), conn); err != nil && request.Context().Err() == nil {
		log.Printf("mio HTTP/1.1 CONNECT %s: %v", request.RemoteAddr, err)
	}
}

type httpCoverConn struct {
	reader  io.Reader
	writer  io.Writer
	request *http.Request
}

func (*httpCoverConn) isCoverStream() {}
func (c *httpCoverConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
func (c *httpCoverConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if flusher, ok := c.writer.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}
func (*httpCoverConn) Close() error                     { return nil }
func (c *httpCoverConn) LocalAddr() net.Addr            { return http3Addr(c.request.Host) }
func (c *httpCoverConn) RemoteAddr() net.Addr           { return http3Addr(c.request.RemoteAddr) }
func (*httpCoverConn) SetDeadline(time.Time) error      { return nil }
func (*httpCoverConn) SetReadDeadline(time.Time) error  { return nil }
func (*httpCoverConn) SetWriteDeadline(time.Time) error { return nil }

func (c *TunnelClient) openTCPCover(ctx context.Context, command byte, target string) (net.Conn, error) {
	if c.hasH2() {
		conn, err := c.roundTripConnect(ctx, c.h2Transport, command, target)
		if err == nil {
			return conn, nil
		}
		var rejected *tunnelRejectedError
		if errors.As(err, &rejected) {
			return nil, err
		}
		log.Printf("HTTP/2 stream unavailable for %s, downgrading to HTTP/1.1: %v", target, err)
		c.dropH2()
	}
	tlsConn, err := c.dialCoverTLS(ctx)
	if err != nil {
		return nil, err
	}
	if tlsConn.ConnectionState().NegotiatedProtocol == coverHTTP2ALPN {
		c.installH2(tlsConn)
		return c.roundTripConnect(ctx, c.h2Transport, command, target)
	}
	return c.openHTTP1Connect(ctx, tlsConn, command, target)
}

func (c *TunnelClient) hasH2() bool {
	c.h2Mu.Lock()
	defer c.h2Mu.Unlock()
	return c.h2Transport != nil && c.h2Conn != nil
}

func (c *TunnelClient) installH2(tlsConn net.Conn) {
	c.h2Mu.Lock()
	defer c.h2Mu.Unlock()
	if c.h2Transport != nil && c.h2Conn != nil {
		_ = tlsConn.Close()
		return
	}
	existing := tlsConn
	c.h2Conn = existing
	c.h2Transport = &http2.Transport{
		AllowHTTP:                  false,
		DisableCompression:         true,
		MaxHeaderListSize:          262144,
		MaxDecoderHeaderTableSize:  65536,
		MaxEncoderHeaderTableSize:  65536,
		StrictMaxConcurrentStreams: true,
		IdleConnTimeout:            30 * time.Second,
		ReadIdleTimeout:            25 * time.Second,
		PingTimeout:                15 * time.Second,
		DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return existing, nil
		},
	}
}

func (c *TunnelClient) dropH2() {
	c.h2Mu.Lock()
	defer c.h2Mu.Unlock()
	if c.h2Transport != nil {
		c.h2Transport.CloseIdleConnections()
	}
	if c.h2Conn != nil {
		_ = c.h2Conn.Close()
	}
	c.h2Transport = nil
	c.h2Conn = nil
}

func (c *TunnelClient) openHTTP1Connect(ctx context.Context, tlsConn net.Conn, command byte, target string) (net.Conn, error) {
	var token bytes.Buffer
	if err := writeRequest(&token, c.key, command, target, time.Now()); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n\r\n",
		c.cover.address, c.cover.host, base64.RawURLEncoding.EncodeToString(token.Bytes()))
	if _, err := tlsConn.Write([]byte(request)); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	buffered := bufio.NewReader(tlsConn)
	response, err := http.ReadResponse(buffered, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("HTTP/1.1 CONNECT rejected: %s", response.Status)
	}
	stream := &prefixConn{Conn: tlsConn, reader: buffered}
	status := []byte{0}
	if _, err := io.ReadFull(stream, status); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if status[0] != 0 {
		_ = tlsConn.Close()
		return nil, &tunnelRejectedError{code: status[0]}
	}
	if command == tunnelCommandTCP {
		return newVision(stream), nil
	}
	return stream, nil
}

func (c *TunnelClient) roundTripConnect(ctx context.Context, transport http.RoundTripper, command byte, target string) (net.Conn, error) {
	var token bytes.Buffer
	if err := writeRequest(&token, c.key, command, target, time.Now()); err != nil {
		return nil, err
	}
	requestReader, requestWriter := newBufferedPipe(h3PipeBuffer)
	streamCtx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, "https://"+c.cover.host+"/", requestReader)
	if err != nil {
		cancel()
		return nil, err
	}
	request.Host = c.cover.host
	request.Header.Set("Proxy-Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(token.Bytes()))
	responseCh := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		response, roundTripErr := transport.RoundTrip(request)
		responseCh <- struct {
			response *http.Response
			err      error
		}{response, roundTripErr}
	}()
	var response *http.Response
	select {
	case result := <-responseCh:
		response, err = result.response, result.err
	case <-ctx.Done():
		cancel()
		_ = requestWriter.CloseWithError(context.Cause(ctx))
		return nil, context.Cause(ctx)
	}
	if err != nil {
		cancel()
		_ = requestWriter.CloseWithError(err)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		cancel()
		_ = requestWriter.Close()
		_ = response.Body.Close()
		return nil, fmt.Errorf("HTTP CONNECT rejected: %s", response.Status)
	}
	streamConn := &httpCoverClientConn{reader: response.Body, writer: requestWriter, cancel: cancel}
	status := []byte{0}
	if _, err := io.ReadFull(streamConn, status); err != nil {
		_ = streamConn.Close()
		return nil, err
	}
	if status[0] != 0 {
		_ = streamConn.Close()
		return nil, &tunnelRejectedError{code: status[0]}
	}
	return streamConn, nil
}

type httpCoverClientConn struct {
	reader    io.ReadCloser
	writer    *bufferedPipeWriter
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func (*httpCoverClientConn) isCoverStream()               {}
func (c *httpCoverClientConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *httpCoverClientConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}
func (c *httpCoverClientConn) Close() error {
	c.closeOnce.Do(func() { c.cancel(); _ = c.writer.Close(); _ = c.reader.Close() })
	return nil
}
func (*httpCoverClientConn) LocalAddr() net.Addr         { return http3Addr("tcp") }
func (*httpCoverClientConn) RemoteAddr() net.Addr        { return http3Addr("tcp") }
func (*httpCoverClientConn) SetDeadline(time.Time) error { return nil }
func (*httpCoverClientConn) SetReadDeadline(time.Time) error {
	return nil
}
func (*httpCoverClientConn) SetWriteDeadline(time.Time) error { return nil }
