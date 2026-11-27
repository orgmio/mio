package client

import (
	"math/rand/v2"
	"time"
)

const (
	minFirstProbeDelay = time.Second
	maxFirstProbeDelay = 10 * time.Second
	minProbeInterval   = 10 * time.Minute
	maxProbeInterval   = 30 * time.Minute
	minFallbackDelay   = 250 * time.Millisecond
	maxFallbackDelay   = time.Second
	probeHeadStart     = 25 * time.Millisecond
)

type transportChoice uint8

const (
	transportTCP transportChoice = iota
	transportQUIC
)

func (t transportChoice) String() string {
	if t == transportQUIC {
		return "QUIC"
	}
	return "TCP"
}

// transportPolicy 由 Dialer.mu 保护，零值首选 TCP。
type transportPolicy struct {
	preferred  transportChoice
	latency    time.Duration
	nextProbe  time.Time
	generation uint64
}

type dialPlan struct {
	preferred, backup transportChoice
	delay             time.Duration
	generation        uint64
}

func (p *transportPolicy) plan(now time.Time) dialPlan {
	delay := min(max(2*p.latency, minFallbackDelay), maxFallbackDelay)
	if !p.nextProbe.IsZero() && now.After(p.nextProbe) {
		delay = probeHeadStart
		p.scheduleProbe(now, minProbeInterval, maxProbeInterval)
	}
	backup := transportQUIC
	if p.preferred == transportQUIC {
		backup = transportTCP
	}
	return dialPlan{preferred: p.preferred, backup: backup, delay: delay, generation: p.generation}
}

func (p *transportPolicy) scheduleProbe(now time.Time, minimum, maximum time.Duration) {
	p.nextProbe = now.Add(minimum + rand.N(maximum-minimum))
}

func (p *transportPolicy) recordSuccess(now time.Time, generation uint64, transport transportChoice, elapsed time.Duration) bool {
	if generation != p.generation {
		return false
	}
	changed := p.preferred != transport
	switch {
	case changed:
		p.preferred = transport
		p.generation++
		p.latency = elapsed
		p.scheduleProbe(now, minProbeInterval, maxProbeInterval)
	case p.latency == 0:
		p.latency = elapsed
		p.scheduleProbe(now, minFirstProbeDelay, maxFirstProbeDelay)
	default:
		p.latency += (elapsed - p.latency) / 4
	}
	return changed
}
