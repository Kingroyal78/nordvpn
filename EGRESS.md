# Sola NordVPN egress

This image replaces the Gluetun Shadowsocks egress on Sola nodes where shoes connects to a host loopback port. Each instance owns one IPv4 WireGuard tunnel and publishes the same TCP and UDP Shadowsocks port to the host. The cipher is `chacha20-ietf-poly1305`. Keep the existing shoes outbound and its password.

## Build or pull

The GitHub Actions workflow publishes `ghcr.io/kingroyal78/nordvpn-egress` for Linux amd64 and arm64. A passing `master` build publishes `sha-<full-commit>`. A passing `egress-v0.1.0` tag publishes `v0.1.0`. The workflow summary lists the digest to pin on the node. For a private package, sign in to GHCR on the node using the deployment account's read-only package credentials.

To build and exercise the image on a Linux development host with Docker, kernel WireGuard, Go 1.26, jq, curl and Python 3:

```bash
docker build -f Dockerfile.egress -t nordvpn-egress:local .
egress/integration.sh nordvpn-egress:local
```

The Compose template uses an isolated Docker bridge, nftables and the kernel WireGuard driver. On the host, load WireGuard with `modprobe wireguard` if it is built as a module. The template sets loose reverse-path filtering inside the container for WireGuard replies arriving on the bridge interface. Attach one Docker bridge and publish TCP and UDP on host loopback with the same port.

## Configure a Sola node

Copy `compose.egress.yml` to a separate project directory on the node. Set its Compose `.env` file to the values for the existing egress. This example shows a Singapore canary on a temporary port.

```dotenv
EGRESS_IMAGE=ghcr.io/kingroyal78/nordvpn-egress@sha256:<digest-from-ci>
SS_HOST_PORT=18473
SERVER_COUNTRIES=Singapore
WIREGUARD_MTU=1280
NORD_SNAPSHOT=/root/gluetun/servers/nordvpn.json
NORD_WG_KEY_FILE=./secrets/wg-key
SS_PASSWORD_FILE=./secrets/ss-password
```

Put the WireGuard private key and existing SS password in separate root-owned files with mode `0600`. Keep the snapshot mounted read-only. A legacy Gluetun `servers.json` containing `nordvpn.servers` also works. To use Gluetun's original mount paths in a custom Compose file, omit `EGRESS_SERVERS_FILE` and mount either `/gluetun/servers/nordvpn.json` or `/gluetun/servers.json`.

| Setting | Behavior |
| --- | --- |
| `SERVER_COUNTRIES`, `SERVER_REGIONS`, `SERVER_CITIES`, `SERVER_HOSTNAMES` | Comma-separated, case-insensitive values. Entries in one field are alternatives, and fields intersect. Configure at least one selector and keep the resulting candidates in a single country. A city selector holds failover to that city. Set `SERVER_HOSTNAMES` to list specific endpoints in preferred order. Dedicated IP servers require explicit hostname selection. |
| `WIREGUARD_PRIVATE_KEY_SECRETFILE`, `SHADOWSOCKS_PASSWORD_SECRETFILE` | The template mounts these paths. For an existing env-file deployment, use either the corresponding unsuffixed variable or its secret file for each credential. |
| `WIREGUARD_ADDRESSES`, `WIREGUARD_MTU`, `WIREGUARD_ENDPOINT_PORT` | Defaults are `10.5.0.2/32`, `1320` and `51820`. Copy overrides from the existing node. |
| `SHADOWSOCKS_LISTENING_ADDRESS` | Defaults to `:8388`. For a custom container port use `:PORT` or `0.0.0.0:PORT` and update the Docker port mappings. |
| `EGRESS_DNS_SERVERS` | Comma-separated IPv4 resolver addresses reached over WireGuard. Defaults to `1.1.1.1,8.8.8.8`. |
| `EGRESS_IP_PROBE_URLS`, `EGRESS_NAME_PROBE_URLS` | Optional overrides for the two probe groups. Each accepts two to eight comma-separated URLs with IPv4 or hostname targets, respectively. The defaults use Cloudflare and Google over HTTPS. |

For the Sola migration, copy only the applicable values into the new configuration. The egress supervisor owns health checks, DNS and recovery timing. The selected snapshot is loaded at startup. To refresh it, update the mount source and recreate the egress container after validating the new candidate set.

## Canary and rollback

1. Save the current Gluetun runtime configuration, container name, restart policy, port, snapshot path and expected exit country. Check account headroom before creating a canary. Use a separate NordVPN key with available capacity for parallel testing, especially if the current service uses the same key and endpoint.
2. Validate the inputs and start the canary on the temporary port.

   ```bash
   docker compose -f compose.egress.yml pull
   docker compose -f compose.egress.yml run --rm --no-deps nordvpn-egress check-config
   docker compose -f compose.egress.yml up -d
   docker compose -f compose.egress.yml exec -T nordvpn-egress nordvpn-egress status
   ```

3. Through the temporary SS port, check actual TCP and UDP egress and the expected exit country. Confirm the intended candidate list has a working standby. On a node whose shoes config uses direct fallback, verify the expected behavior with the VPN down before treating it as a fail-closed deployment.
4. In the cutover window, stop the old Gluetun service and keep its container and files for rollback. Change `SS_HOST_PORT` to the original port and use the original credential files for production. Run `docker compose -f compose.egress.yml up -d`, then verify the real Sola client over TCP and UDP, exit country, and panel heartbeats. Observe the node for 24 hours and compare outage count and recovery times with the previous baseline.
5. For an unexpected exit country, persistent outage or direct egress, stop the new Compose service, restore the saved Gluetun restart policy, and start Gluetun on the original port. Verify the Sola client and panel again.

The status reports the active endpoint, last handshake, DNS and proxy probe results, consecutive failures, switch count and last success. Three consecutive failed rounds make the endpoint unhealthy and drive failover. Two successful rounds restore readiness. If every configured candidate fails, the supervisor backs off between sweeps. Established connections can reset when the exit changes.
