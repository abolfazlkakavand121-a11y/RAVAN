# RAVAN Protocol Analyzer — first milestone

## Goal

Combine the existing DNS, TCP, TLS, and HTTP diagnostics into one ordered analysis so a failed connection can be localized to a network stage before adding any transport experiments.

## Command

```sh
ravan analyze https://example.com/
ravan analyze https://example.com/ --json
ravan analyze http://example.com/
```

## Execution order

For HTTPS URLs:

1. Resolve the hostname with the device's system resolver.
2. Establish a TCP connection to the URL's effective port.
3. Perform TLS with normal certificate-chain and hostname validation.
4. Send the existing bounded HTTP HEAD diagnostic and record the response status.

For HTTP URLs, the TLS stage is omitted.

The analyzer stops at the first failed stage and reports the completed stages. It does not silently switch DNS providers, change routes, retry through another proxy, or alter packets.

## Interpretation

- DNS failure: name resolution did not complete.
- TCP failure: the hostname was resolved, but a TCP connection was not established.
- TLS failure: TCP worked, but TLS negotiation or certificate validation failed.
- HTTP exchange success: an HTTP response was received. HTTP 403/404 are still successful transport/application exchanges and must not be misclassified as a network failure.
- HTTP exchange failure: transport setup completed, but the HTTP request/response stage did not.

## Deliberate limitations

This is a staged connectivity analyzer, not yet a deep protocol fingerprinting or censorship-detection engine. It does not inspect packet payloads, decrypt traffic, perform TLS interception, probe arbitrary ports, use UDP/QUIC, fragment traffic, or attempt evasion. It runs through the device's normal direct network path; it does not use the RAVAN SOCKS5 listener as its own route.

The DNS/TCP/TLS/HTTP stages are separate probes and may establish separate connections. Results localize a likely failing stage but do not prove why a network or destination rejected it.

## Next milestones

- Add controlled IPv4/IPv6 comparison and preserve per-address outcomes.
- Add repeated, bounded measurements to distinguish intermittent failures from stable failures.
- Feed evidence into a Detection Engine only after the analyzer's output is validated on real networks.
