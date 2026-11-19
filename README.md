# RAVAN

RAVAN is an experimental, independent network diagnostics and local connectivity toolkit for Android and Termux, written in Rust.

## Project status

The first Rust engine includes the CLI, local SOCKS5 TCP proxy, configuration handling, and DNS/TCP/TLS/HTTP diagnostics. The Android ARM64 build and the earlier analyzer milestone were installed and exercised on a Termux device. Each new analyzer change still requires its own device-side verification.

The hosted CI pipeline checks Rust formatting, runs Clippy and automated tests, builds the Android ARM64 target, and audits dependencies. These checks do not establish reachability on a real mobile network.

## Initial commands

- ravan doctor
- ravan config init
- ravan config show
- ravan proxy
- ravan diag dns example.com
- ravan diag tcp example.com:443
- ravan diag tls example.com:443
- ravan diag http https://example.com/
- ravan analyze https://example.com/ (per-IP DNS/TCP/TLS/HTTP analysis)

Diagnostic commands accept an optional --json flag.

## Protocol Analyzer v0.3

The analyzer resolves a hostname once, keeps the resulting IP addresses separate, and pins each TCP, TLS, and HTTP probe to the same selected IP. TLS still uses the original hostname for SNI and normal certificate verification.

Examples:

- ravan analyze https://example.com/ --ip-family all
- ravan analyze https://example.com/ --ip-family ipv4
- ravan analyze https://example.com/ --ip-family ipv6
- ravan analyze https://example.com/ --ip-family all --repeats 3 --json

The --repeats range is 1-5 and defaults to 1. The pinned HTTP probe records redirects but does not follow them, because a redirect may change hosts and break the single-IP trial. The standalone ravan diag http command retains its existing redirect behavior.

See docs/PROTOCOL-ANALYZER-v0.3.0.md.

## Important limitations

RAVAN is not a censorship-circumvention guarantee. A local proxy cannot restore reachability when a destination is blocked at the routing/IP layer, and it cannot bypass destination-side regional restrictions without an appropriate remote network path.

The v0.1.0 proxy forwards TCP bytes; it does not decrypt or modify TLS. It supports SOCKS5 TCP CONNECT only, binds to loopback only, and does not provide UDP, QUIC, or system-wide VPN routing.

TLS diagnostics validate certificate chains and hostnames using public roots. RAVAN does not install a custom certificate authority or disable certificate verification.

A successful cross-build does not prove that the latest binary runs on Termux, and neither a build nor a diagnostic proves filtering bypass. Actual device testing remains a release gate for every milestone.

## Build and validation

- Android ARM64 cross-build: aarch64-linux-android
- Android NDK: 30.0.16248370 (r30 LTS), API 21 baseline
- Rust dependency versions are pinned in Cargo.lock
- GitHub Actions uploads the Android ARM64 binary, archive, and SHA-256 checksum as a workflow artifact

A successful Android cross-build is not the same as a runtime test on a physical Termux device.

## Technical specification and tests

- Technical specification: docs/SPECIFICATION-v0.1.0.md
- Test plan and current coverage: docs/TESTING-v0.1.0.md
- Android ARM64 build instructions and validation status: docs/ANDROID-BUILD.md

## Security

See SECURITY.md. Do not commit passwords, tokens, private keys, or other secrets.
