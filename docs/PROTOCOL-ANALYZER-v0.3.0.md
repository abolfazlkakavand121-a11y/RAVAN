# RAVAN Protocol Analyzer v0.3.0 — pinned IP and address-family comparison

## Goal

The v0.3 analyzer compares IPv4 and IPv6 paths independently and records outcomes for each resolved IP address. Each address trial is pinned to one SocketAddr so the TCP, TLS, and HTTP stages do not perform fresh DNS lookups that could select different endpoints.

## Commands

Run every address family returned by the system resolver:

    ravan analyze https://example.com/
    ravan analyze https://example.com/ --json

Test only IPv4 or IPv6:

    ravan analyze https://example.com/ --ip-family ipv4
    ravan analyze https://example.com/ --ip-family ipv6

Repeat each selected IP address sequentially (1-5 attempts; default 1):

    ravan analyze https://example.com/ --ip-family all --repeats 3 --json

## Execution model

1. Resolve the URL hostname once using the device's system resolver.
2. Record all returned IP addresses and filter them according to --ip-family.
3. For each selected IP, run the configured number of sequential attempts.
4. In each attempt, connect TCP to that exact IP and URL port.
5. For HTTPS, establish TLS to the same IP while retaining the original URL hostname for SNI and certificate hostname validation.
6. Send one HTTP HEAD request to the same IP and original URL host.

Each stage opens its own connection, but all connections within one address attempt target the same pinned IP. This ensures that DNS rotation or resolver ordering cannot silently move later stages to another IP.

## HTTP redirects

The pinned HTTP probe records whether a redirect was returned, but does not follow it. A redirect may point to a different hostname and following it would break the single-IP trial guarantee. A valid HTTP response, including a 3xx, 403, or 404 response, confirms that the HTTP server responded; it is not itself a transport failure.

The existing standalone ravan diag http command retains its redirect-following behavior.

## Report interpretation

- The DNS section contains all resolved addresses plus the addresses selected for the requested family.
- Each IP has an independent report and per-attempt stage list.
- A TCP failure prevents TLS and HTTP for that attempt; a TLS failure prevents HTTP.
- An IP is marked successful when at least one complete attempt reaches the HTTP response stage.
- The overall analysis is successful when at least one selected IP completes an attempt. Other IPs may still have failures; inspect the per-address results.
- Repeats are sequential to avoid intentionally creating a burst of concurrent probes.

## Safety and scope

The analyzer uses the device's normal network route. It does not use the RAVAN SOCKS5 listener, change DNS providers, alter routing, inspect packet payloads, decrypt traffic, install a certificate authority, disable TLS verification, or attempt filtering evasion.

It does not use UDP or QUIC. It is a connectivity measurement tool, not a guarantee of availability or a censorship-detection verdict. Results can vary by destination, network, resolver, and time.

## Next milestone

Validate these per-address results on real networks, then use the structured evidence as input to the Detection Engine. The analyzer should be validated before automatic route selection or transport adaptation is introduced.
