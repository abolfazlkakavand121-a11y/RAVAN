# RAVAN

RAVAN is an experimental, independent network diagnostics and local connectivity toolkit for Android and Termux, written in Rust.

## Project status

RAVAN **v0.3.0** is an experimental Rust networking tool for Android and Termux. It currently includes the CLI, a local SOCKS5 TCP forwarder, configuration handling, DNS/TCP/TLS/HTTP diagnostics, and the Protocol Analyzer with per-address IP pinning and redirect-hop reporting.

The hosted CI pipeline checks formatting, runs Clippy and automated tests, builds a Linux release binary, and cross-builds Android ARM64. The Android binary has also been run manually on a Termux device: analyzer checks for IPv4/IPv6 and redirect handling passed, and the SOCKS5 listener was tested with several HTTPS destinations. These results demonstrate the tested paths only; they do not guarantee connectivity on every network.

## Initial commands

- ravan doctor
- ravan config init
- ravan config show
- ravan proxy
- ravan diag dns example.com
- ravan diag tcp example.com:443
- ravan diag tls example.com:443
- ravan diag http https://example.com/
- ravan analyze https://example.com/ (staged DNS/TCP/TLS/HTTP analysis)

Diagnostic commands accept an optional --json flag.

## Important limitations

RAVAN is not a censorship-circumvention guarantee. A local proxy cannot restore reachability when a destination is blocked at the routing/IP layer, and it cannot bypass destination-side regional restrictions without an appropriate remote network path.

The v0.3.0 local proxy forwards TCP bytes; it does not decrypt or modify TLS. It supports SOCKS5 TCP CONNECT only, binds to loopback only, and does not provide UDP, QUIC, an HTTP proxy listener, or system-wide VPN routing.

TLS diagnostics validate certificate chains and hostnames using public roots. RAVAN does not install a custom certificate authority or disable certificate verification.

A successful cross-build does not prove that the binary runs on Termux, and neither a build nor a diagnostic proves filtering bypass. Actual Termux device testing is a release gate.

## Build and validation

- Android ARM64 cross-build: `aarch64-linux-android`
- Android NDK: `30.0.16248370` (r30 LTS), API 21 baseline
- Rust dependency versions are pinned in `Cargo.lock`
- GitHub Actions uploads the Android ARM64 binary, archive, and SHA-256 checksum as a 30-day workflow artifact

A successful Android cross-build is not the same as a runtime test on a physical Termux device.

## Protocol Analyzer (first milestone)

The `ravan analyze` command runs DNS, TCP, TLS (for HTTPS), and HTTP checks against each selected address. The initial connection is pinned to the selected IP while preserving the hostname for TLS verification; redirect destinations are resolved and pinned independently. Use `--ip-family both|ipv4|ipv6` to select the address family. The analyzer does not perform deep packet inspection, traffic modification, UDP/QUIC, or filtering evasion. See [Protocol Analyzer design](docs/PROTOCOL-ANALYZER-v0.2.0.md).

## Technical specification and tests

- [Technical specification](docs/SPECIFICATION-v0.1.0.md)
- [Test plan and current coverage](docs/TESTING-v0.1.0.md)
- [Android ARM64 build instructions and validation status](docs/ANDROID-BUILD.md)

## Security

See SECURITY.md. Do not commit passwords, tokens, private keys, or other secrets.
