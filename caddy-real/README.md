# Capture metadata

## way-brave-caddy.pcapng

- Captured: 2026-08-03
- Profile: cold, fresh browser user-data directory
- Brave: 1.93.129 (official, x86_64)
- Chromium: 151.0.7922.71
- Origin: `local.867678.xyz`
- Caddy TLS: internal CA
- TCP JA4: `t13d1516h2_8daaf6152771_806a8c22fdea`
- QUIC JA4: `q13d0311h3_55b375c5d22e_653d80c3fe9d`
- Client QUIC Initial packet size: 1250 bytes
- TCP-to-QUIC delay observed: about 429 ms

The capture includes a cold HTTP/2 page load and a successful QUIC handshake.
The first navigation continues on HTTP/2 after QUIC becomes available; capture
a second navigation separately when documenting warm HTTP/3 traffic.

## Download

Because this file is so large, here using Cloudflare R2 to document distribution

> Always dynamic latest

brave-visit-caddy:`https://r2.867678.xyz/pcap/way-brave-caddy.pcapng`

hysteria2:`https://r2.867678.xyz/pcap/way-hysteria2.pcapng`

ixa:`https://r2.867678.xyz/pcap/way-ixa.pcapng`

> SHA256

0a1da5dec15558b03e113c5c7e66bf0c7c9be105f813983f29616bd0ae74bed7  caddy-real/way-brave-caddy.pcapng
645a20bbc721a36dd035527fa215f49b17546ff8ffd800db3aa2c87500444ea9  caddy-real/way-hysteria2.pcapng
eb6168fc030bb09cc74330a992702d473143390be66c666a6d053f1a8364beaf  caddy-real/way-ixa.pcapng