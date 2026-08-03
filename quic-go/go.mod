module github.com/quic-go/quic-go

go 1.25.0

require (
	github.com/quic-go/go-ossfuzz-seeds v0.1.0
	github.com/quic-go/qpack v0.6.0
	github.com/refraction-networking/utls v1.8.2
	github.com/stretchr/testify v1.11.1
	go.uber.org/mock v0.5.2
	golang.org/x/crypto v0.53.0
	golang.org/x/net v0.56.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	go.uber.org/mock/mockgen
)

replace github.com/refraction-networking/utls => ../utls
