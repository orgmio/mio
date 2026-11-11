module github.com/orgmio/mio

go 1.27.3

require (
	github.com/apernet/quic-go v0.65.1-0.20261109005002-2895f039137a
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/refraction-networking/utls v1.8.2
	github.com/things-go/go-socks5 v0.1.4
	golang.org/x/exp v0.0.0-20261109185158-a52e3aef5920
)

replace github.com/apernet/quic-go => github.com/HyNetworks/quic-go v0.65.1-0.20261109005002-2895f039137a

require (
	github.com/andybalholm/brotli v1.3.0 // indirect
	github.com/klauspost/compress v1.20.4 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)
