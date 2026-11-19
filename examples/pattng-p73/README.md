# PattNG P73 / RAVAN SOCKS5 test profile (Xray only)

This is an **Xray-core** custom profile for PattNG **v2.4.0-P73**. It connects the Xray TUN inbound to RAVAN's local SOCKS5 TCP listener.

## Required runtime settings

1. Use **Xray core** in PattNG. Sing-box is not supported by this JSON.
2. Use **Xray TUN** mode. Keep **HEV TUN disabled**. PattNG's HEV mode starts a separate tun2socks path and does not pass the Android VPN file descriptor to Xray; this profile contains an Xray `tun` inbound and no HEV-compatible local SOCKS inbound.
3. RAVAN must run in Termux on the same Android device and listen on `127.0.0.1:2080`.
4. **Exclude Termux from PattNG's VPN routing.** In PattNG, enable per-app routing, choose the mode that bypasses selected apps, and add Termux (usually package `com.termux`) to the bypass list. Then reconnect the VPN.

   This step is essential when RAVAN runs as a separate Termux process. PattNG's Android VPN service excludes PattNG itself by default, but it does not automatically exclude Termux. Without the exclusion, RAVAN's own outbound sockets can be captured by the same VPN whose traffic is being sent to RAVAN, creating a recursive route/connection loop. RAVAN cannot call PattNG's `VpnService.protect()` from a separate Termux process.

## Start and import

1. In Termux, run `./ravan-android-arm64 proxy` and leave it running. Confirm it prints `RAVAN SOCKS5 listening on 127.0.0.1:2080`.
2. In PattNG, add a **Custom Config** profile.
3. Paste [ravan-socks5-tcp.json](./ravan-socks5-tcp.json) into the custom configuration editor and save it.
4. Select the profile, confirm Xray core + Xray TUN mode + Termux bypass, and connect.

No SOCKS username or password is configured.

## What this profile routes

- TCP from the Xray TUN inbound is explicitly sent through RAVAN's SOCKS5 listener.
- DNS on port 53 is sent directly through the device network, outside RAVAN. If the network blocks that DNS path, name resolution can still fail; a later DNS-over-HTTPS design must be separately tested.
- Non-DNS UDP is blocked because RAVAN v0.4.0 implements SOCKS5 TCP CONNECT only, not UDP ASSOCIATE.
- QUIC/HTTP/3 is therefore not carried by RAVAN; applications may fall back to TCP when supported.

## Important limitation: this does not itself bypass filtering

The path is:

`Android apps -> PattNG TUN/Xray -> RAVAN SOCKS5 (127.0.0.1:2080) -> direct TCP connection to destination`

RAVAN v0.4.0 is a local TCP relay. It does not add a remote server, encrypted tunnel, alternate network path, or filtering-evasion transport. Excluding Termux fixes the Android VPN recursion problem; it does **not** make blocked destination IPs reachable. A destination that the device network cannot reach directly will still fail until a separate, reachable remote transport/peer is implemented.

This profile is a diagnostic Xray-only TCP profile, not a complete VPN configuration or a filtering-bypass guarantee.
