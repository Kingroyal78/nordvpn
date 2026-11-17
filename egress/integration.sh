#!/usr/bin/env bash
set -euo pipefail

image=${1:-nordvpn-egress:local}
project=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
name="sola-e2e-$$"
work=$(mktemp -d)
egress="$name-egress"
client="$name-client"
first="$name-first"
second="$name-second"

cleanup() {
    local status=$?
    if (( status != 0 )); then
        docker logs "$egress" >&2 || true
        docker logs "$client" >&2 || true
        docker logs "$first" >&2 || true
        docker logs "$second" >&2 || true
    fi
    docker rm -f "$client" "$egress" "$first" "$second" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

wait_until() {
    local deadline=$((SECONDS + $1))
    shift
    until "$@"; do
        if (( SECONDS >= deadline )); then
            printf 'Timed out waiting for %s\n' "$*" >&2
            return 1
        fi
        sleep 1
    done
}

loopback_port() {
    python3 - <<'PY'
import socket
while True:
    with socket.socket() as stream, socket.socket(type=socket.SOCK_DGRAM) as datagram:
        stream.bind(("127.0.0.1", 0))
        port = stream.getsockname()[1]
        try:
            datagram.bind(("127.0.0.1", port))
        except OSError:
            continue
        print(port)
        break
PY
}

public_key() {
    docker run --rm -i --network none --entrypoint wg "$image" pubkey
}

bridge_ip() {
    docker inspect -f "{{(index .NetworkSettings.Networks \"$name\").IPAddress}}" "$1"
}

start_peer() {
    docker run -d --name "$1" --network "$name" --cap-add NET_ADMIN --entrypoint /bin/sh \
        -e "PEER_NAME=$2" -e "CLIENT_PUBLIC_KEY=$client_public" \
        --mount "type=bind,source=$work/$2.key,target=/test/wg.key,readonly" \
        --mount "type=bind,source=$work/fixture,target=/test/fixture,readonly" "$image" -ec '
            ip link add dev wgpeer type wireguard
            ip addr add 10.5.0.1/32 dev wgpeer
            wg set wgpeer private-key /test/wg.key listen-port 51820 peer "$CLIENT_PUBLIC_KEY" allowed-ips 10.5.0.2/32
            ip link set dev wgpeer up
            ip route add 10.5.0.2/32 dev wgpeer
            exec /test/fixture
        ' >/dev/null
}

ready_on() {
    docker exec "$egress" nordvpn-egress status 2>/dev/null |
        jq -e --arg peer "$1" '.ready and .endpoint == $peer' >/dev/null
}

is_unhealthy() {
    [[ $(docker inspect -f '{{.State.Health.Status}}' "$egress") == unhealthy ]]
}

client_tcp() {
    curl -fsS --max-time 4 --socks5-hostname "127.0.0.1:$socks_port" http://peer.test:8080/which 2>/dev/null
}

# Send a DNS request through the published SS UDP port via SOCKS5 UDP ASSOCIATE.
client_udp() {
    python3 - "$socks_port" <<'PY'
import socket
import struct
import sys

def receive(stream, size):
    data = b""
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError("short SOCKS5 reply")
        data += chunk
    return data

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=4) as control:
    control.sendall(b"\x05\x01\x00")
    assert receive(control, 2) == b"\x05\x00"
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    assert receive(control, 4) == b"\x05\x00\x00\x01"
    reply_ip = socket.inet_ntoa(receive(control, 4))
    reply_port, = struct.unpack("!H", receive(control, 2))
    query = bytes.fromhex("556601000001000000000000") + b"\x04peer\x04test\x00\x00\x01\x00\x01"
    socks_header = b"\x00\x00\x00\x01" + socket.inet_aton("10.5.0.1") + struct.pack("!H", 53)
    with socket.socket(type=socket.SOCK_DGRAM) as udp:
        udp.settimeout(4)
        udp.sendto(socks_header + query, (reply_ip, reply_port))
        packet, _ = udp.recvfrom(512)
    assert packet.startswith(socks_header + b"\x55\x66\x81\x80")
    assert packet[-4:] == socket.inet_aton("10.5.0.1")
PY
}

no_direct_egress() {
    if curl -fsS --max-time 3 --socks5-hostname "127.0.0.1:$socks_port" "http://$first_ip:8080/which" 2>/dev/null; then
        printf 'Proxied TCP escaped through the underlay\n' >&2
        return 1
    fi
    if docker exec "$egress" busybox wget -qO- -T 2 "http://$first_ip:8080/which"; then
        printf 'TCP escaped through the underlay\n' >&2
        return 1
    fi
    if docker exec "$egress" timeout 2 busybox nslookup example.com "$first_ip" >/dev/null 2>&1; then
        printf 'DNS escaped through the underlay\n' >&2
        return 1
    fi
    if docker exec "$egress" timeout 2 busybox nslookup "$first" 127.0.0.11 >/dev/null 2>&1; then
        printf 'DNS escaped through the Docker resolver\n' >&2
        return 1
    fi
}

(cd "$project" && CGO_ENABLED=0 go build -o "$work/fixture" ./testfixture)
chmod 0700 "$work"
for key in egress primary standby; do
    docker run --rm --network none --entrypoint wg "$image" genkey > "$work/$key.key"
    chmod 0600 "$work/$key.key"
done
client_public=$(public_key < "$work/egress.key")
test_private_key=$(<"$work/egress.key")
first_public=$(public_key < "$work/primary.key")
second_public=$(public_key < "$work/standby.key")
docker network create "$name" >/dev/null
start_peer "$first" primary
start_peer "$second" standby
first_ip=$(bridge_ip "$first")
second_ip=$(bridge_ip "$second")
wait_until 10 curl -fsS --max-time 2 "http://$first_ip:8080/which"
printf '\n'
# A healthy underlay is the positive control for the later leak tests.
docker exec "$second" timeout 3 busybox nslookup example.com "$first_ip" >/dev/null
docker exec "$second" timeout 3 busybox nslookup "$first" 127.0.0.11 >/dev/null

jq -n --arg a "$first_ip" --arg b "$second_ip" --arg ak "$first_public" --arg bk "$second_public" '
    def peer($name; $ip; $key):
      {vpn:"wireguard",country:"Testland",region:"Test",city:"Example",hostname:$name,ips:[$ip],wgpubkey:$key};
    {servers:[peer("primary.test";$a;$ak),peer("standby.test";$b;$bk)]}
' > "$work/nordvpn.json"
password=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
printf '%s\n' "$password" > "$work/password"
chmod 0600 "$work/password"
# CI runners create files as an unprivileged host UID. The production
# container reads root-owned secret files without CAP_DAC_OVERRIDE.
docker run --rm --network none --entrypoint /bin/sh \
    --mount "type=bind,source=$work,target=/test" "$image" \
    -ec 'chown 0:0 /test/egress.key /test/password'

ss_port=$(loopback_port)
socks_port=$(loopback_port)
jq -n --arg pass "$password" --argjson ss "$ss_port" --argjson socks "$socks_port" '
    {server:"127.0.0.1",server_port:$ss,method:"chacha20-ietf-poly1305",password:$pass,
     mode:"tcp_and_udp",local_address:"127.0.0.1",local_port:$socks}
' > "$work/client.json"
chmod 0600 "$work/client.json"

config=(
    --mount "type=bind,source=$work/nordvpn.json,target=/gluetun/servers/nordvpn.json,readonly"
    --mount "type=bind,source=$work/egress.key,target=/run/secrets/wg,readonly"
    --mount "type=bind,source=$work/password,target=/run/secrets/ss,readonly"
    -e WIREGUARD_PRIVATE_KEY_SECRETFILE=/run/secrets/wg
    -e SHADOWSOCKS_PASSWORD_SECRETFILE=/run/secrets/ss
    -e SERVER_COUNTRIES=Testland -e 'SERVER_HOSTNAMES=primary.test,standby.test'
    -e EGRESS_DNS_SERVERS=10.5.0.1
    -e 'EGRESS_IP_PROBE_URLS=http://10.5.0.1:8080/unavailable,http://10.5.0.1:8080/probe'
    -e 'EGRESS_NAME_PROBE_URLS=http://first.test:8080/unavailable,http://second.test:8080/probe'
)
capabilities=(--cap-drop ALL --cap-add NET_ADMIN --cap-add CHOWN --cap-add SETUID --cap-add SETGID)
docker run --rm --network none "${capabilities[@]}" "${config[@]}" "$image" check-config |
    jq -e '.country == "Testland" and .candidates == 2 and .port == 8388' >/dev/null
if docker run --rm --network none "${config[@]}" -e SERVER_CITIES=missing "$image" check-config; then
    printf 'Invalid selection was accepted\n' >&2
    exit 1
fi

docker run -d --name "$egress" --network "$name" --init "${capabilities[@]}" \
    --read-only --tmpfs /run:rw,nosuid,nodev,noexec --security-opt no-new-privileges=true \
    --sysctl net.ipv4.conf.all.rp_filter=2 \
    -p "127.0.0.1:$ss_port:8388/tcp" -p "127.0.0.1:$ss_port:8388/udp" "${config[@]}" "$image" >/dev/null
docker run -d --name "$client" --network host --entrypoint sslocal \
    --mount "type=bind,source=$work/client.json,target=/test/client.json,readonly" "$image" -c /test/client.json >/dev/null

wait_until 40 ready_on primary.test
wait_until 15 docker exec "$egress" nordvpn-egress healthcheck
[[ $(client_tcp) == "primary 10.5.0.2" ]]
client_udp
printf 'TCP, UDP, DNS and redundant probes passed on the primary endpoint\n'

docker exec "$first" touch /tmp/block-proxy
wait_until 60 ready_on standby.test
[[ $(client_tcp) == "standby 10.5.0.2" ]]
client_udp
docker logs "$egress" 2>&1 | jq -es '
    any(.[]; .msg == "switching WireGuard endpoint" and .reason == "proxy_egress")
' >/dev/null
printf 'Recovered on standby after a proxy failure with a live handshake\n'

docker exec "$first" ip link set wgpeer down
docker exec "$second" ip link set wgpeer down
wait_until 45 is_unhealthy
docker exec "$egress" ip link del wg0
no_direct_egress
printf 'TCP and DNS remained blocked without the WireGuard route\n'

docker exec "$first" ip link set wgpeer up
docker exec "$first" ip route replace 10.5.0.2/32 dev wgpeer
docker exec "$first" rm /tmp/block-proxy
docker restart "$egress" >/dev/null
wait_until 40 ready_on primary.test
[[ $(client_tcp) == "primary 10.5.0.2" ]]
client_udp
docker logs "$egress" > "$work/egress.log" 2>&1
if grep -qF -- "$password" "$work/egress.log"; then
    printf 'Logs contain the Shadowsocks password\n' >&2
    exit 1
fi
if grep -qF -- "$test_private_key" "$work/egress.log"; then
    printf 'Logs contain the WireGuard private key\n' >&2
    exit 1
fi
printf 'Restart recovery and credential redaction passed\n'
