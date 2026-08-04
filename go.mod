module github.com/moaeiou/ixa-go

go 1.26.5

require github.com/pelletier/go-toml/v2 v2.4.3

require github.com/quic-go/quic-go v0.61.0

require github.com/refraction-networking/utls v1.8.2

require (
	github.com/hashicorp/yamux v0.1.2
	github.com/things-go/go-socks5 v0.1.1
	golang.org/x/sys v0.47.0
)

require (
	github.com/andybalholm/brotli v1.2.2 // indirect
	github.com/klauspost/compress v1.19.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/refraction-networking/utls => ./utls

replace github.com/quic-go/quic-go => ./quic-go
