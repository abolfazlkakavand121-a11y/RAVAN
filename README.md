# RAVAN

RAVAN is an experimental, independent network diagnostics and local connectivity toolkit for Android and Termux, written in Rust.

## Project status

The initial Rust engine is under development. The repository contains the first implementation of the CLI, local SOCKS5 TCP proxy, configuration handling, and DNS/TCP/TLS/HTTP diagnostic modules. It has not yet been compiled or tested on a Termux device.

## Initial commands

- ravan doctor
- ravan config init
- ravan config show
- ravan proxy
- ravan diag dns example.com
- ravan diag tcp example.com:443
- ravan diag tls example.com:443
- ravan diag http https://example.com/

Diagnostic commands accept an optional --json flag.

## Important limitations

RAVAN is not a censorship-circumvention guarantee. A local proxy cannot restore reachability when a destination is blocked at the routing/IP layer, and it cannot bypass destination-side regional restrictions without an appropriate remote network path.

The v0.1.0 proxy forwards TCP bytes; it does not decrypt or modify TLS. It supports SOCKS5 TCP CONNECT only, binds to loopback only, and does not provide UDP, QUIC, or system-wide VPN routing.

TLS diagnostics validate certificate chains and hostnames using public roots. RAVAN does not install a custom certificate authority or disable certificate verification.

A successful cross-build does not prove that the binary runs on Termux, and neither a build nor a diagnostic proves filtering bypass. Actual Termux device testing is a release gate.

## Technical specification

See docs/SPECIFICATION-v0.1.0.md for the intended first-release scope, behavior, security requirements, and acceptance criteria.

## Security

See SECURITY.md. Do not commit passwords, tokens, private keys, or other secrets.
