package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	uplink       = "eth0"
	tunnel       = "wg0"
	tunnelMark   = "0x51820"
	routingTable = "51820"
	firewall     = "nordvpn_egress"
)

func command(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	// Command arguments and input can include deployment details. Keep errors bounded.
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, args[0], err)
	}
	return output, nil
}

func runCommand(ctx context.Context, input, name string, args ...string) error {
	_, err := command(ctx, input, name, args...)
	return err
}

func bridgeGateway(ctx context.Context) (netip.Addr, error) {
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns == "net:[4026531840]" {
		return netip.Addr{}, errors.New("an isolated Docker bridge network namespace is required")
	}
	links, err := command(ctx, "", "ip", "-json", "-details", "link", "show", "dev", uplink)
	if err != nil {
		return netip.Addr{}, err
	}
	var interfaces []struct {
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal(links, &interfaces) != nil || len(interfaces) != 1 || interfaces[0].LinkInfo.Kind != "veth" {
		return netip.Addr{}, errors.New("eth0 is not a Docker bridge veth")
	}
	output, err := command(ctx, "", "ip", "-json", "-4", "route", "show", "default")
	if err != nil {
		return netip.Addr{}, err
	}
	var routes []struct {
		Gateway netip.Addr `json:"gateway"`
		Device  string     `json:"dev"`
	}
	if json.Unmarshal(output, &routes) != nil || len(routes) != 1 || routes[0].Device != uplink || !routes[0].Gateway.Is4() {
		return netip.Addr{}, errors.New("one IPv4 default route via the Docker bridge is required")
	}
	return routes[0].Gateway, nil
}

func installFirewall(ctx context.Context, cfg config, gateway netip.Addr) error {
	rules := fmt.Sprintf(`
add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	set endpoint { type ipv4_addr; }
	chain ingress {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname "%[2]s" ip saddr %[3]s tcp dport %[4]d accept
		iifname "%[2]s" ip saddr %[3]s udp dport %[4]d accept
		iifname "%[2]s" ip saddr @endpoint udp sport %[5]d ct state established accept
		iifname "%[2]s" ip protocol icmp ct state related accept
		iifname "%[6]s" meta nfproto ipv4 ct state established,related accept
	}
	chain egress {
		type filter hook output priority filter; policy drop;
		ip daddr 127.0.0.11 drop
		oifname "lo" accept
		oifname "%[6]s" meta nfproto ipv4 accept
		oifname "%[2]s" ip daddr @endpoint udp dport %[5]d meta mark %[7]s accept
		oifname "%[2]s" ip daddr %[3]s ct direction reply tcp sport %[4]d accept
		oifname "%[2]s" ip daddr %[3]s ct direction reply udp sport %[4]d accept
	}
	chain forwarding {
		type filter hook forward priority filter; policy drop;
	}
}
`, firewall, uplink, gateway, cfg.SSPort, cfg.PeerPort, tunnel, tunnelMark)
	return runCommand(ctx, rules, "nft", "-f", "-")
}

func configureNetwork(ctx context.Context, cfg config) error {
	gateway, err := bridgeGateway(ctx)
	if err != nil {
		return err
	}
	if err := installFirewall(ctx, cfg, gateway); err != nil {
		return fmt.Errorf("install the kill switch: %w", err)
	}
	if _, err := net.InterfaceByName(tunnel); err == nil {
		if err := runCommand(ctx, "", "ip", "link", "del", "dev", tunnel); err != nil {
			return err
		}
	}
	// The main table supplies the bridge's connected route and the marked
	// WireGuard socket's default route. Normal traffic uses the tunnel table.
	mainRule := []string{"priority", "100", "lookup", "main", "suppress_prefixlength", "0"}
	tunnelRule := []string{"priority", "110", "not", "fwmark", tunnelMark, "lookup", routingTable}
	for _, rule := range [][]string{mainRule, tunnelRule} {
		_ = runCommand(ctx, "", "ip", append([]string{"-4", "rule", "del"}, rule...)...)
	}
	for _, args := range [][]string{
		{"link", "add", "dev", tunnel, "type", "wireguard"},
		{"-4", "addr", "add", cfg.Address.String(), "dev", tunnel},
		{"link", "set", "dev", tunnel, "mtu", strconv.Itoa(cfg.MTU), "up"},
		{"-4", "route", "replace", "default", "dev", tunnel, "table", routingTable},
		append([]string{"-4", "rule", "add"}, mainRule...),
		append([]string{"-4", "rule", "add"}, tunnelRule...),
	} {
		if err := runCommand(ctx, "", "ip", args...); err != nil {
			return fmt.Errorf("configure WireGuard device and routes: %w", err)
		}
	}
	return runCommand(ctx, cfg.PrivateKey+"\n", "wg", "set", tunnel, "private-key", "/dev/stdin", "fwmark", tunnelMark)
}

func activatePeer(ctx context.Context, old *peer, next peer, port int) error {
	// Replace the allowlist in one transaction. While the peer is being
	// replaced the egress filter remains in place and the route stays on wg0.
	rules := fmt.Sprintf("flush set inet %s endpoint\nadd element inet %s endpoint { %s }\n", firewall, firewall, next.IP)
	if err := runCommand(ctx, rules, "nft", "-f", "-"); err != nil {
		return err
	}
	if old != nil {
		if err := runCommand(ctx, "", "wg", "set", tunnel, "peer", old.Key, "remove"); err != nil {
			return err
		}
	}
	endpoint := netip.AddrPortFrom(next.IP, uint16(port))
	return runCommand(ctx, "", "wg", "set", tunnel, "peer", next.Key, "endpoint", endpoint.String(),
		"allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25")
}

func latestHandshake(ctx context.Context) time.Time {
	data, err := command(ctx, "", "wg", "show", tunnel, "latest-handshakes")
	fields := strings.Fields(string(data))
	if err != nil || len(fields) != 2 {
		return time.Time{}
	}
	seconds, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}
