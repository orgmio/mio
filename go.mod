module github.com/orgmio/mio

go 1.27.4

require (
	github.com/apernet/quic-go v0.65.1-0.20261109005002-2895f039137a
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/refraction-networking/utls v1.8.2
	github.com/spf13/cobra v1.10.2
	github.com/things-go/go-socks5 v0.1.4
	golang.org/x/exp v0.0.0-20261113113407-e3970619a1a4
)

replace github.com/apernet/quic-go => github.com/HyNetworks/quic-go v0.65.1-0.20261109005002-2895f039137a

require (
	github.com/andybalholm/brotli v1.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.20.4 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)
