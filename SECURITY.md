# Security Policy

## Scope

RAVAN v0.1.0 is a local Termux network utility. Its SOCKS5 listener must bind only to loopback, and its TLS diagnostics must validate certificate chains and hostnames normally.

RAVAN does not perform TLS interception, install a custom CA, disable certificate verification, or upload diagnostic data.

## Reporting

Please report suspected vulnerabilities privately to the repository owner rather than publishing exploit details in an issue. Include the affected version, platform, reproduction steps, and a concise impact description.

Do not include passwords, private keys, access tokens, or unrelated personal data in reports.
