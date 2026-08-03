# ixa quic-go fork

This directory is based on `github.com/quic-go/quic-go` v0.61.0.

ixa-specific changes:

- per-client, ordered opaque QUIC transport parameters through
  `Config.AdditionalClientTransportParameters`;
- opt-in Chromium QUIC ClientHello generation through uTLS with
  `Config.UseChromeClientHello`;
- Brave 1.93 / Chromium 151 client transport-parameter ordering, values and
  eight-byte Initial destination connection IDs when that mode is enabled;
- future QUIC handshake fingerprint work is kept here instead of patching the
  module cache or relying on process-global state.

Keep upstream-facing changes small and record every behavioral patch in this
file when rebasing the fork.
