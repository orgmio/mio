package mio

import (
	"net"
	"testing"

	tlsfork "github.com/orgmio/utls-mio"
)

// TestBraveClientHelloExtensionOrder pins the extension order of the TCP
// cover ClientHello to the real Brave capture in
// caddy-real/way-brave-caddy-baidu.pcapng. utls's HelloChrome_Auto shuffles
// extensions; reorderBraveExtensions must restore the fixed Brave order.
func TestBraveClientHelloExtensionOrder(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()

	uconn := tlsfork.UClient(raw, &tlsfork.Config{
		MinVersion:         tlsfork.VersionTLS13,
		ServerName:         "local.867678.xyz",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, tlsfork.HelloChrome_Auto)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	applyBraveSigAlgs(uconn)
	reorderBraveExtensions(uconn)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}

	if len(uconn.Extensions) != 18 {
		t.Fatalf("got %d extensions, want 18", len(uconn.Extensions))
	}
	prev := -1
	for i, ext := range uconn.Extensions {
		rank := braveExtensionRank(ext)
		if rank <= prev {
			t.Fatalf("extension %d (rank %d) out of Brave order (previous rank %d): %T", i, rank, prev, ext)
		}
		prev = rank
	}
}
