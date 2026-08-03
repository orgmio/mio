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
