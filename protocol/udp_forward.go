package mio

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

const udpFallbackIdleTimeout = 2 * time.Minute

type udpReplyWriter interface {
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

type udpForwardSession struct {
	upstream net.Conn
	client   *net.UDPAddr
	mu       sync.Mutex
	lastSeen time.Time
}

func (s *TunnelServer) forwardUDP(ctx context.Context, writer udpReplyWriter, client *net.UDPAddr, payload []byte) error {
	key := client.String()
	s.udpMu.Lock()
	session := s.udpSessions[key]
	if session == nil {
		upstream, err := s.dialContext(ctx, "udp", s.cover.address)
		if err != nil {
			s.udpMu.Unlock()
			return err
		}
		session = &udpForwardSession{upstream: upstream, client: cloneUDPAddr(client), lastSeen: time.Now()}
		s.udpSessions[key] = session
		go s.relayUDP(key, session, writer)
		log.Printf("UDP fallback %s -> %s", client, s.cover.address)
	}
	s.udpMu.Unlock()

	session.mu.Lock()
	session.lastSeen = time.Now()
	_, err := session.upstream.Write(payload)
	session.mu.Unlock()
	if err != nil {
		s.dropUDP(key, session)
	}
	return err
}

func (s *TunnelServer) relayUDP(key string, session *udpForwardSession, writer udpReplyWriter) {
	buffer := make([]byte, maxUDPPayload)
	for {
		n, err := session.upstream.Read(buffer)
		if err != nil {
			s.dropUDP(key, session)
			return
		}
		session.mu.Lock()
		session.lastSeen = time.Now()
		session.mu.Unlock()
		if _, err := writer.WriteToUDP(buffer[:n], session.client); err != nil {
			s.dropUDP(key, session)
			return
		}
	}
}

func (s *TunnelServer) expireUDP(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.udpMu.Lock()
			for key, session := range s.udpSessions {
				session.mu.Lock()
				idle := now.Sub(session.lastSeen)
				session.mu.Unlock()
				if idle >= udpFallbackIdleTimeout {
					delete(s.udpSessions, key)
					_ = session.upstream.Close()
				}
			}
			s.udpMu.Unlock()
		}
	}
}

func (s *TunnelServer) dropUDP(key string, expected *udpForwardSession) {
	s.udpMu.Lock()
	if s.udpSessions[key] == expected {
		delete(s.udpSessions, key)
		_ = expected.upstream.Close()
	}
	s.udpMu.Unlock()
}

func (s *TunnelServer) closeUDP() {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	for key, session := range s.udpSessions {
		delete(s.udpSessions, key)
		_ = session.upstream.Close()
	}
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}
