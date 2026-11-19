# RAVAN v0.1.0 — Test Plan and Current Coverage

This document distinguishes automated local tests from device and network validation.

## Automated tests

The automated suite is designed to run without contacting public hosts. SOCKS5 integration tests use loopback TCP listeners and ephemeral ports.

Coverage includes:

- SOCKS5 no-authentication negotiation and rejection when the client offers no supported method.
- CONNECT-only policy and protocol replies for unsupported commands.
- Rejection of malformed reserved fields and unsupported address types.
- Rejection of empty, non-UTF-8, and zero-port destination values.
- Parsing a domain-name CONNECT request without relying on external DNS.
- A real loopback TCP CONNECT with payload transfer in both directions.
- Loopback-only listener configuration and bounded timeout/connection settings.
- Diagnostic target parsing, IPv6 host normalization, and removal of credentials/query data from displayed targets.

Run locally with:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

## What these tests do not prove

A successful CI run does **not** prove:

- That the binary runs on every Android/Termux version or device.
- That Android ARM64 cross-compilation is configured or successful.
- That a mobile operator, Wi-Fi network, DNS resolver, CDN, or destination permits a given connection.
- That RAVAN bypasses filtering or can restore a route that is blocked upstream.
- That IPv6 works on every carrier or that every SOCKS5 client behaves identically.

Those require separate Android/Termux and real-network tests. No external network endpoint is contacted by the loopback SOCKS5 integration tests.

## Manual device test gate

Before calling the SOCKS5 proxy device-validated, test on an actual ARM64 Termux installation:

1. Run `ravan doctor` and record its output.
2. Start `ravan proxy` and confirm it binds only to `127.0.0.1:2080`.
3. Configure a local test client to use SOCKS5 at `127.0.0.1:2080`.
4. Confirm a known reachable HTTPS destination transfers data.
5. Stop RAVAN with Ctrl+C and confirm the listener exits.
6. Repeat with Wi-Fi and mobile data separately; record failures without interpreting them as proof of filtering.

Do not use a public or untrusted network listener. RAVAN's unauthenticated SOCKS5 mode is intended for loopback use only.
