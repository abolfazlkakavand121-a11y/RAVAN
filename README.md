# RAVAN

RAVAN is an experimental, independent network diagnostics and local connectivity toolkit for Android and Termux, written in Rust.

## Project status

Specification phase for v0.1.0. No executable engine or release binary has been published yet.

The first milestone is intentionally focused:
- A loopback-only SOCKS5 TCP CONNECT proxy.
- DNS, TCP, TLS, and HTTP/HTTPS diagnostics.
- Safe local configuration and privacy-conscious reports.
- Reproducible checks and Android ARM64 build validation.
- A verified Termux installation path after real-device testing.

## Important limitations

RAVAN is not a censorship-circumvention guarantee. A local proxy cannot restore reachability when a destination is blocked at the routing/IP layer, and it cannot bypass destination-side regional restrictions without an appropriate remote network path.

The v0.1.0 proxy forwards TCP bytes; it does not decrypt or modify TLS. RAVAN will not install a custom certificate authority or disable normal certificate and hostname verification.

A successful cross-build only proves that the source compiled. It does not prove that the binary runs on Termux, and it does not prove that a network path bypasses filtering. Actual Termux device testing is a release gate.

## Technical specification

See [docs/SPECIFICATION-v0.1.0.md](docs/SPECIFICATION-v0.1.0.md) for the approved first-release scope, command contract, architecture, security requirements, and acceptance criteria.

## Security

Do not expose the local proxy on public interfaces. Do not commit passwords, tokens, private keys, or other secrets. Security issues should be reported privately to the repository owner.
