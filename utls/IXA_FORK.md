# ixa-go uTLS fork

This directory is based on `github.com/refraction-networking/utls` v1.8.2.
The upstream BSD license is retained in `LICENSE`.

ixa-go adds `Config.InsecureSkipCertificateVerify`. When enabled, the TLS 1.3
client keeps the CertificateVerify message in the handshake transcript but
does not validate its signature against the certificate public key.

This option is intentionally narrow. ixa-go enables it only for its tunnel
client and authenticates the server independently with the HMAC carried in
ServerHello.Random and bound to ClientHello.Random. It must not be used by a
general-purpose TLS client.
