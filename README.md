# NordVPN Egress

A Docker image that provides a **Shadowsocks (SS) proxy over NordVPN WireGuard**. The image includes the official NordVPN Linux CLI and daemon.

## Features

- Shadowsocks TCP and UDP relay with the `chacha20-ietf-poly1305` cipher. The sample Compose file publishes both protocols on the same host loopback port.
- Kernel WireGuard with endpoint selection from a read-only server snapshot and automatic failover within the configured location.
- Health checks for WireGuard handshakes, DNS and proxy egress. A kill switch blocks traffic outside the tunnel.
- Native container images for Linux `amd64` and `arm64`.

## Getting started

The published image is `ghcr.io/kingroyal78/nordvpn-egress:v0.1.0`. The Compose template accepts a server snapshot, a WireGuard private key and a Shadowsocks password. It mounts credentials as files by default. [Configuration and deployment guide](EGRESS.md) · [Compose template](compose.egress.yml)

To check the bundled NordVPN client version:

```sh
docker run --rm --network none --entrypoint nordvpn \
  ghcr.io/kingroyal78/nordvpn-egress:v0.1.0 --version
```

The egress service manages its own WireGuard tunnel. The NordVPN daemon is included and starts separately when explicitly invoked.

## Legacy image

The earlier NordVPN CLI container is documented in the upstream project. [Legacy documentation](https://github.com/bubuntux/nordvpn)
