# RAVAN

RAVAN is an experimental, independent network diagnostics and local connectivity toolkit for Android and Termux.

## Project status

Early development. The first milestone focuses on a reliable local SOCKS5 proxy, transparent diagnostics, reproducible builds, and a verified Termux installer.

RAVAN does not use TLS interception or install a custom certificate authority. TLS connections must retain normal certificate and hostname verification.

## Important limitations

RAVAN is not a censorship-circumvention guarantee. A local proxy cannot restore reachability when a destination is blocked at the routing/IP layer, nor can it bypass destination-side regional restrictions without an appropriate remote network path.

A successful build only proves that the source compiled and tests passed; it does not prove that a network path bypasses filtering.

## Planned first milestone

- Standalone Go implementation; no Xray dependency.
- Local SOCKS5 listener bound to loopback only.
- DNS, TCP, TLS, and HTTP connectivity diagnostics.
- Termux-friendly installation and lifecycle commands.
- Automated tests and Android/Termux-target build validation through GitHub Actions.

## Security

Do not expose the local proxy on public interfaces. Do not commit passwords, tokens, private keys, or other secrets. Report security issues privately to the repository owner.
