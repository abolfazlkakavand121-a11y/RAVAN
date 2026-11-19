# PattNG P73 / RAVAN SOCKS5 test profile

This is a diagnostic Xray JSON profile for **PattNG v2.4.0-P73** with the current RAVAN local SOCKS5 listener.

## Requirements

- RAVAN must already be running on the same Android device.
- RAVAN must listen on `127.0.0.1:2080`.
- The current RAVAN build supports TCP CONNECT only. It does not implement SOCKS5 UDP ASSOCIATE.

## Import

1. Start RAVAN in Termux and confirm that it prints `RAVAN SOCKS5 listening on 127.0.0.1:2080`.
2. In PattNG, add a **Custom Config** profile.
3. Paste the contents of [ravan-socks5-tcp.json](./ravan-socks5-tcp.json) into the custom configuration editor and save it.
4. Select that profile and start PattNG in VPN mode.

No SOCKS username or password is configured.

## Routing behavior (intentional diagnostic limitations)

- TCP traffic other than port 53 is sent to RAVAN's SOCKS5 listener.
- DNS traffic on port 53 is sent directly through the device network so name resolution can work during this TCP-only test.
- Other UDP traffic is blocked. It is **not** sent through RAVAN because the current RAVAN version has no UDP support.
- QUIC/HTTP/3 therefore is not carried by RAVAN; applications may fall back to TCP when supported.
- This profile is for diagnosis, not a complete VPN configuration and not a filtering-bypass guarantee. DNS on port 53 is outside RAVAN by design.

## Important

This profile tests the path:

`Android apps -> PattNG TUN/Xray -> RAVAN SOCKS5 (127.0.0.1:2080) -> destination TCP`

It does not create a remote proxy chain and does not include any server credentials. Chaining a remote profile through RAVAN is a separate configuration that must be built around that remote profile's actual protocol and settings.
