# RAVAN v0.1.0 — Technical Specification

**Status:** Approved MVP scope for implementation planning  
**Date:** 2026-11-19  
**Language:** Rust  
**Primary platform:** Android / Termux, ARM64

This is a specification, not evidence that any feature has already been implemented or tested.

## 1. Product goal

RAVAN v0.1.0 is a small, auditable network utility for Termux. It combines:
1. A loopback-only SOCKS5 TCP proxy for applications that already support SOCKS5.
2. Explicit diagnostics for DNS, TCP, TLS, and HTTP/HTTPS.
3. Clear, privacy-conscious results that identify which connection stage succeeds or fails.

The first release prioritizes correctness, predictable behavior, low resource use, and an extensible foundation.

RAVAN does not promise to bypass filtering. A local proxy cannot create a route to an IP address that the network cannot reach, and it cannot remove destination-side regional restrictions without another network path.

## 2. v0.1.0 scope

### Included
- Rust command-line application for Termux.
- Primary device architecture: 64-bit ARM (AArch64).
- SOCKS5 server supporting TCP CONNECT only.
- Default listener: 127.0.0.1:2080.
- Loopback-only bind validation; non-loopback listener addresses are rejected.
- SOCKS5 destination address types: IPv4, IPv6, and domain name.
- Domain names are resolved by the device's Android/Termux system resolver.
- DNS, TCP-connect, TLS-handshake, and HTTP(S) diagnostics.
- Human-readable terminal output and optional JSON diagnostic output.
- TOML configuration with safe defaults.
- Structured local logs with sensitive URL components redacted.
- Automated unit and integration tests.
- GitHub Actions checks and an Android ARM64 cross-compilation job.
- A Termux installation path only after the release artifact passes real-device validation.

### Explicitly excluded
- Android VPN Service / TUN and transparent routing of every application.
- Root access or changes to Android system networking.
- UDP forwarding, SOCKS5 BIND, and SOCKS5 UDP ASSOCIATE.
- HTTP proxy mode.
- TLS interception, custom CA installation, certificate bypass, or hostname-verification bypass.
- QUIC, custom transports, protocol obfuscation, traffic shaping, or automatic evasion.
- Remote servers, relays, tunnels, VPN exits, or a required VPS.
- Automatic switching between experimental connection methods.
- A graphical Android application.
- Claims that a successful diagnostic or build proves censorship circumvention.

These items may be considered in later versions after separate design and evidence-based testing.

## 3. Initial command contract

The intended command surface is:

| Command | Expected behavior |
|---|---|
| ravan --version | Print application version and build information. |
| ravan doctor | Check local runtime, configuration, and listener prerequisites. Do not silently run broad internet tests. |
| ravan proxy | Start the SOCKS5 listener in the foreground; stop with Ctrl+C. |
| ravan proxy --listen 127.0.0.1:2080 | Start the listener on an explicit loopback address. |
| ravan diag dns example.com | Resolve using the device's system resolver and report duration and returned addresses. |
| ravan diag tcp example.com:443 | Attempt TCP connection and report result, failure class, and duration. |
| ravan diag tls example.com:443 | Perform TLS handshake with normal certificate-chain and hostname validation. |
| ravan diag http https://example.com/ | Send an HTTP HEAD request and report response status and timing; do not save the response body. |
| ravan config init | Create a default config without overwriting an existing file. |
| ravan config show | Display effective non-secret settings. |

Exact flag names and help wording may be refined during implementation, but these behaviors and safety constraints are normative.

Diagnostics run directly through the device's normal network path in v0.1.0. They do not automatically route through the RAVAN SOCKS5 listener. A diagnostic result must identify the tested target and phase.

## 4. SOCKS5 behavior

The proxy implements SOCKS Version 5 for TCP CONNECT only.

- It accepts the no-authentication method because the service is bound only to loopback.
- It rejects clients that do not offer the supported method.
- It accepts CONNECT destinations using IPv4, IPv6, and domain-name address types.
- Domain names are resolved on the device using the system resolver.
- It returns protocol-appropriate success or failure replies.
- After a successful CONNECT, it forwards bytes in both directions without inspecting, rewriting, logging, or decrypting application payloads.
- Unsupported commands, including BIND and UDP ASSOCIATE, are rejected explicitly.
- Malformed requests, oversized protocol fields, timeouts, and connection failures must not cause panics.
- The listener must bind only to an IP address that is actually loopback (127.0.0.1 or ::1). It must never fall back to 0.0.0.0, ::, or a LAN address.
- Initial defaults: 5-second SOCKS handshake timeout, 10-second outbound TCP connect timeout, and a bounded concurrent-connection limit (initial default 128). These values must be configurable only within safe bounds.
- Ctrl+C stops accepting new clients, closes the listening socket, allows active sessions up to two seconds to finish, then cancels remaining sessions; shutdown behavior is covered by tests.

The proxy is a byte-forwarding TCP relay. It does not improve reachability, change the device's public IP, or provide a remote exit.

## 5. Diagnostics behavior

### DNS
- Use the operating system resolver available to the Termux process.
- Report lookup duration and returned IPv4/IPv6 addresses.
- Distinguish resolver errors from later TCP or TLS errors.
- Do not silently switch to a hard-coded public DNS server.

### TCP
- Attempt a normal TCP connection to the exact host and port supplied.
- Report connection duration and a useful error category (for example: name resolution, timeout, refused, or other I/O failure).
- Close the test connection after recording the result.

### TLS
- Connect to the requested host and port and perform a client TLS handshake.
- Send the correct SNI for DNS hostnames.
- Validate the certificate chain and hostname against a documented public root store.
- Never provide an option to ignore invalid certificates or hostname mismatches.
- Report handshake outcome, elapsed time, and negotiated TLS details when available.
- Do not expose session secrets or application data.

### HTTP / HTTPS
- Accept only HTTP and HTTPS URLs.
- Use a HEAD request for the first milestone; report the HTTP status and timing.
- A valid HTTP error status, such as 403 or 404, proves that an HTTP server responded; it is not the same as a DNS, TCP, or TLS failure.
- Follow at most three redirects and enforce a 15-second overall deadline across the entire redirect chain.
- Do not download or retain response bodies.
- Never print URL query strings or user-info credentials in normal logs.

Diagnostics must distinguish transport reachability from application authorization. For example, HTTP 403 means an HTTP response was received; it does not mean the network connection failed.

## 6. Configuration and local data

- Configuration format: TOML.
- Default config location: HOME/.config/ravan/config.toml, respecting XDG_CONFIG_HOME when set.
- Logs and optional reports remain under the user's home directory, using XDG state conventions where available.
- Do not store credentials in the default configuration.
- Config initialization must not overwrite an existing file.
- Config display and diagnostic output must redact secrets and URL credentials.
- Diagnostic reports may contain timestamp, RAVAN version, command, target hostname/port, phase, result, elapsed time, and sanitized error category.
- Do not collect contacts, messages, installed-app lists, device identifiers, MAC addresses, or browsing history.
- No telemetry or background data upload in v0.1.0.

## 7. Security and privacy requirements

- No TLS MITM, custom CA, certificate substitution, or disabled certificate checks.
- No public-interface proxy listener.
- No shell command assembled from untrusted hostnames, ports, or configuration values.
- Validate command-line and configuration input before opening sockets.
- Use bounded buffers, bounded concurrency, timeouts, and explicit error handling.
- Do not log raw payloads, authorization headers, cookies, URL user-info, or URL query strings.
- Use maintained crates with narrow feature sets; commit Cargo.lock for the executable.
- Run formatting, Clippy, tests, and dependency/security review in CI.
- Never claim a security property or filtering capability that has not been tested.

## 8. Internal architecture

Keep these boundaries separate:
- cli: command parsing and user-facing help.
- config: configuration loading, defaults, validation, and paths.
- proxy: SOCKS5 protocol handling and TCP stream forwarding.
- diagnostics: separate DNS, TCP, TLS, and HTTP probes.
- report: stable diagnostic result types and sanitized output.
- runtime: startup, shutdown, tracing, and shared limits.

The v0.1.0 network path is direct. Keep proxying and diagnostics decoupled and use stable internal result types so later transport adapters can be added. Do not build a plugin framework or speculative transport abstraction before a second real implementation justifies it.

## 9. Build and platform policy

- Primary release candidate: Android AArch64 / Termux.
- Rust Android target: aarch64-linux-android, cross-compiled with the Android NDK from a supported host environment.
- Host CI runs formatting, Clippy, unit tests, and integration tests.
- CI cross-compiles the Android ARM64 binary.
- Cross-compilation success is not proof that the binary runs correctly in Termux. A real Termux ARM64 smoke test is a release gate.
- If the cross-compiled artifact is not compatible with the tested Termux environment, use a Termux-native build or adjust toolchain/linking; do not publish an unverified binary as supported.
- Pin the Rust toolchain and GitHub Actions versions when implementation begins.
- Keep artifacts separate from source and publish SHA-256 checksums with releases.

Official Rust Android target documentation: https://doc.rust-lang.org/rustc/platform-support/android.html

## 10. Acceptance criteria for v0.1.0

A release candidate is not ready until:
1. It builds reproducibly for the chosen Android ARM64 target.
2. It starts and exits cleanly in a real Termux ARM64 environment.
3. The proxy rejects non-loopback bind addresses.
4. SOCKS5 tests cover negotiation, IPv4, IPv6, domain names, CONNECT success, unsupported commands, malformed input, timeouts, and connect failures.
5. A local test client transfers data in both directions through the proxy without corruption.
6. DNS, TCP, TLS, and HTTP diagnostics distinguish their respective failure stages.
7. TLS tests prove that invalid certificates and hostname mismatches are rejected.
8. Unit and integration tests pass in CI.
9. Installation verifies the downloaded artifact's SHA-256 before placing it in PREFIX/bin.
10. The README accurately describes limitations and makes no promise to bypass filtering.

A CI build without device execution must be labeled compiled, not Termux-tested.

## 11. Deliberately postponed roadmap

After v0.1.0 has been tested, possible follow-up work includes:
- Optional diagnostics through a running local SOCKS5 proxy.
- Additional transport experiments, each isolated and independently measured.
- Evidence-based selection or combination of connection methods.
- UDP or QUIC support after separate protocol and security review.
- An Android application using VPN Service / TUN for system-wide routing.
- A graphical interface and guided troubleshooting.

No postponed feature is implied to exist in v0.1.0.

## 12. Definition of success

The first success is not “works against every filter.” It is a reliable, understandable, secure local tool that runs on the target Termux environment, reports exactly which network stage succeeds or fails, and provides a maintainable base for carefully tested future connection methods.
