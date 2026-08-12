package mio

import (
	"encoding/binary"
	"testing"
)

func TestBraveQUICTransportParameters(t *testing.T) {
	params := braveParams()
	if len(params) != 2 {
		t.Fatalf("got %d transport parameters, want 2", len(params))
	}
	if params[0].ID != 0x11 || len(params[0].Value) != 12 {
		t.Fatalf("invalid version_information parameter: %#v", params[0])
	}
	if got := binary.BigEndian.Uint32(params[0].Value[:4]); got != 1 {
		t.Fatalf("chosen QUIC version = %#x, want v1", got)
	}
	grease := params[0].Value[4:8]
	for _, b := range grease {
		if b&0x0f != 0x0a {
			t.Fatalf("invalid GREASE version %x", grease)
		}
	}
	if got := binary.BigEndian.Uint32(params[0].Value[8:]); got != 1 {
		t.Fatalf("supported QUIC version = %#x, want v1", got)
	}
	if params[1].ID != 0x3128 || string(params[1].Value) != "ORIG" {
		t.Fatalf("invalid Google connection options parameter: %#v", params[1])
	}
}
