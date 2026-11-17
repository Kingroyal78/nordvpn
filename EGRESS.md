# NordVPN Egress deployment

Each container runs an IPv4 WireGuard tunnel and publishes a Shadowsocks proxy for TCP and UDP. Configure the client with the published host address and port, the configured password, and the `chacha20-ietf-poly1305` cipher.

## Build or pull

GitHub Actions publishes `ghcr.io/kingroyal78/nordvpn-egress` for Linux amd64 and arm64. A passing `master` build publishes `sha-<full-commit>`. A passing `egress-v0.1.0` tag publishes `v0.1.0`. The workflow summary lists the image digest for version pinning.

The Debian-based image installs the official NordVPN Linux CLI and daemon from the signed NordVPN stable APT repository. `NORDVPN_VERSION` in the Dockerfile pins the package across both architectures. The egress process configures the kernel WireGuard tunnel, routing and firewall in its container.

To build and test on a Linux host with Docker, kernel WireGuard, Go 1.26, jq, curl and Python 3:

```sh
docker build -f Dockerfile.egress -t nordvpn-egress:local .
egress/integration.sh nordvpn-egress:local
```

The Compose template uses an isolated Docker bridge, nftables and kernel WireGuard. On the host, load WireGuard with `modprobe wireguard` if it is built as a module. The template sets loose reverse-path filtering inside the container for WireGuard replies arriving on the bridge. Keep the TCP and UDP port mappings on host loopback.

## Configure

Place `compose.egress.yml` in a project directory and set its Compose `.env` file. Replace the country placeholder with a value from your snapshot.

```dotenv
EGRESS_IMAGE=ghcr.io/kingroyal78/nordvpn-egress:v0.1.0
SS_HOST_PORT=8388
SERVER_COUNTRIES=<country-from-snapshot>
NORD_SNAPSHOT=./servers/nordvpn.json
NORD_WG_KEY_FILE=./secrets/wg-key
SS_PASSWORD_FILE=./secrets/ss-password
```

For a digest-pinned installation, set `EGRESS_IMAGE` to `ghcr.io/kingroyal78/nordvpn-egress@sha256:<manifest-digest>`. Store the WireGuard private key and Shadowsocks password in separate root-owned files with mode `0600`. The template mounts the server snapshot read-only.

| Setting | Behavior |
| --- | --- |
| `SERVER_COUNTRIES`, `SERVER_REGIONS`, `SERVER_CITIES`, `SERVER_HOSTNAMES` | Comma-separated, case-insensitive values. Entries in one field are alternatives, and fields intersect. Set at least one selector and keep the resulting candidates in a single country. A city selector restricts failover to that city. A hostname list sets endpoint preference and can explicitly select Dedicated IP servers. |
| `WIREGUARD_PRIVATE_KEY_SECRETFILE`, `SHADOWSOCKS_PASSWORD_SECRETFILE` | The template mounts both credentials as files. Each credential also accepts the corresponding unsuffixed variable as an alternative. |
| `WIREGUARD_ADDRESSES`, `WIREGUARD_MTU`, `WIREGUARD_ENDPOINT_PORT` | Defaults to `10.5.0.2/32`, `1320` and `51820`, respectively. |
| `SHADOWSOCKS_LISTENING_ADDRESS` | Defaults to `:8388`. A custom container port uses `:PORT` or `0.0.0.0:PORT` and matching Docker port mappings. |
| `EGRESS_SERVERS_FILE` | Accepts a provider snapshot with a top-level `servers` array or a legacy snapshot containing `nordvpn.servers`. Custom deployments can also use the compatible container paths `/gluetun/servers/nordvpn.json` or `/gluetun/servers.json`. |
| `EGRESS_DNS_SERVERS` | Comma-separated IPv4 resolver addresses reached over WireGuard. Defaults to `1.1.1.1,8.8.8.8`. |
| `EGRESS_IP_PROBE_URLS`, `EGRESS_NAME_PROBE_URLS` | Overrides for the two HTTP(S) probe groups. Each accepts two to eight comma-separated URLs with IPv4 or hostname targets, respectively. The defaults use Cloudflare and Google over HTTPS. |

The selected snapshot loads at startup. To refresh it, update the mount source, run the configuration check and recreate the container.

## Start and inspect

```sh
docker compose -f compose.egress.yml pull
docker compose -f compose.egress.yml run --rm --no-deps nordvpn-egress check-config
docker compose -f compose.egress.yml up -d
docker compose -f compose.egress.yml exec -T nordvpn-egress nordvpn-egress status
```

The status reports the active endpoint, last handshake, DNS and proxy probe results, consecutive failures, switch count and last success. Three consecutive failed rounds make the endpoint unhealthy and drive failover. Two successful rounds restore readiness. If every configured endpoint fails, the supervisor backs off between sweeps. Established connections can reset when the endpoint changes.
