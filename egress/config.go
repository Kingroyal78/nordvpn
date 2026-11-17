package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	proxyPort         = 1080
	defaultCipher     = "chacha20-ietf-poly1305"
	providerWireGuard = "wireguard"
)

type config struct {
	PrivateKey string
	Password   string
	Address    netip.Prefix
	MTU        int
	SSPort     int
	PeerPort   int
	DNS        []string
	IPProbes   []string
	NameProbes []string
	Peers      []peer
}

type peer struct {
	Hostname string
	Country  string
	IP       netip.Addr
	Key      string
}

type serverRecord struct {
	VPN         string   `json:"vpn"`
	Hostname    string   `json:"hostname"`
	Country     string   `json:"country"`
	Region      string   `json:"region"`
	City        string   `json:"city"`
	Categories  []string `json:"categories"`
	IPAddresses []string `json:"ips"`
	Key         string   `json:"wgpubkey"`
}

type snapshot struct {
	Servers []serverRecord `json:"servers"`
}

type selection struct {
	countries []string
	regions   []string
	cities    []string
	hostnames []string
}

var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func splitList(value string) []string {
	var values []string
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

func secret(name string) (string, error) {
	file, value := os.Getenv(name+"_SECRETFILE"), os.Getenv(name)
	if file != "" && value != "" {
		return "", fmt.Errorf("set only one of %s and %s_SECRETFILE", name, name)
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("cannot read %s_SECRETFILE", name)
		}
		value = strings.TrimRight(string(data), "\r\n")
	}
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func validKey(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == value &&
		!slices.Equal(decoded, make([]byte, 32))
}

func integer(name, value string, min, max int) (int, error) {
	number, err := strconv.Atoi(value)
	if err != nil || number < min || number > max {
		return 0, fmt.Errorf("%s must be between %d and %d", name, min, max)
	}
	return number, nil
}

func probeURLs(name, defaults string, numeric bool) ([]string, error) {
	values := splitList(envOr(name, defaults))
	if len(values) < 2 || len(values) > 8 {
		return nil, fmt.Errorf("%s requires two to eight URLs", name)
	}
	seen := make(map[string]bool)
	for _, value := range values {
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("%s requires HTTP(S) URLs without credentials or fragments", name)
		}
		address, err := netip.ParseAddr(u.Hostname())
		if (numeric && (err != nil || !address.Is4())) || (!numeric && (err == nil || !hostnamePattern.MatchString(u.Hostname()))) {
			return nil, fmt.Errorf("%s has an unexpected target address type", name)
		}
		if seen[value] {
			return nil, fmt.Errorf("%s contains a duplicate URL", name)
		}
		seen[value] = true
	}
	return values, nil
}

func loadConfig() (config, error) {
	var cfg config
	for _, option := range []struct{ name, expected string }{
		{"VPN_TYPE", "wireguard"}, {"VPN_SERVICE_PROVIDER", "nordvpn"},
		{"SHADOWSOCKS", "on"}, {"SHADOWSOCKS_CIPHER", defaultCipher},
	} {
		if !strings.EqualFold(envOr(option.name, option.expected), option.expected) {
			return cfg, fmt.Errorf("%s must be %s", option.name, option.expected)
		}
	}

	var err error
	cfg.PrivateKey, err = secret("WIREGUARD_PRIVATE_KEY")
	if err != nil {
		return cfg, err
	}
	if !validKey(cfg.PrivateKey) {
		return cfg, errors.New("WIREGUARD_PRIVATE_KEY must be a nonzero base64 WireGuard key")
	}
	cfg.Password, err = secret("SHADOWSOCKS_PASSWORD")
	if err != nil {
		return cfg, err
	}
	cfg.Address, err = netip.ParsePrefix(envOr("WIREGUARD_ADDRESSES", "10.5.0.2/32"))
	if err != nil || !cfg.Address.Addr().Is4() || cfg.Address.Addr().IsUnspecified() || cfg.Address.Addr().IsLoopback() {
		return cfg, errors.New("WIREGUARD_ADDRESSES must be one IPv4 interface address in CIDR notation")
	}
	cfg.MTU, err = integer("WIREGUARD_MTU", envOr("WIREGUARD_MTU", "1320"), 576, 9000)
	if err != nil {
		return cfg, err
	}
	cfg.PeerPort, err = integer("WIREGUARD_ENDPOINT_PORT", envOr("WIREGUARD_ENDPOINT_PORT", "51820"), 1, 65535)
	if err != nil {
		return cfg, err
	}
	listenHost, listenPort, err := net.SplitHostPort(envOr("SHADOWSOCKS_LISTENING_ADDRESS", ":8388"))
	if err != nil || (listenHost != "" && listenHost != "0.0.0.0") {
		return cfg, errors.New("SHADOWSOCKS_LISTENING_ADDRESS must be :PORT or 0.0.0.0:PORT")
	}
	cfg.SSPort, err = integer("Shadowsocks port", listenPort, 1024, 65535)
	if err != nil {
		return cfg, err
	}
	if cfg.SSPort == proxyPort {
		return cfg, errors.New("Shadowsocks port 1080 is reserved for the local health client")
	}

	cfg.DNS = splitList(envOr("EGRESS_DNS_SERVERS", "1.1.1.1,8.8.8.8"))
	if len(cfg.DNS) == 0 || len(cfg.DNS) > 4 {
		return cfg, errors.New("EGRESS_DNS_SERVERS requires one to four IPv4 resolver addresses")
	}
	for _, value := range cfg.DNS {
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return cfg, errors.New("EGRESS_DNS_SERVERS requires IPv4 resolver addresses reachable through the tunnel")
		}
	}
	cfg.IPProbes, err = probeURLs("EGRESS_IP_PROBE_URLS", "https://1.1.1.1/cdn-cgi/trace,https://8.8.8.8/resolve?name=example.com&type=A", true)
	if err != nil {
		return cfg, err
	}
	cfg.NameProbes, err = probeURLs("EGRESS_NAME_PROBE_URLS", "https://www.cloudflare.com/cdn-cgi/trace,https://dns.google/resolve?name=example.com&type=A", false)
	if err != nil {
		return cfg, err
	}
	selected := selection{
		countries: splitList(os.Getenv("SERVER_COUNTRIES")),
		regions:   splitList(os.Getenv("SERVER_REGIONS")),
		cities:    splitList(os.Getenv("SERVER_CITIES")),
		hostnames: splitList(os.Getenv("SERVER_HOSTNAMES")),
	}
	if len(selected.countries)+len(selected.regions)+len(selected.cities)+len(selected.hostnames) == 0 {
		return cfg, errors.New("set at least one SERVER_COUNTRIES, SERVER_REGIONS, SERVER_CITIES or SERVER_HOSTNAMES selector")
	}
	cfg.Peers, err = loadPeers(os.Getenv("EGRESS_SERVERS_FILE"), selected)
	return cfg, err
}

func loadPeers(path string, selected selection) ([]peer, error) {
	if path == "" {
		path = "/gluetun/servers/nordvpn.json"
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			path = "/gluetun/servers.json"
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read NordVPN server snapshot; mount a Gluetun snapshot or set EGRESS_SERVERS_FILE")
	}
	return parsePeers(data, selected)
}

func matches(values []string, candidate string) bool {
	return len(values) == 0 || slices.ContainsFunc(values, func(value string) bool {
		return strings.EqualFold(value, candidate)
	})
}

func parsePeers(data []byte, selected selection) ([]peer, error) {
	var file struct {
		snapshot
		NordVPN *snapshot `json:"nordvpn"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, errors.New("invalid NordVPN server snapshot JSON")
	}
	records := file.Servers
	if file.NordVPN != nil {
		records = file.NordVPN.Servers
	}
	var peers []peer
	countries := make(map[string]bool)
	seen := make(map[struct {
		address netip.Addr
		key     string
	}]bool)
	for _, record := range records {
		if record.VPN != providerWireGuard || !matches(selected.countries, record.Country) ||
			!matches(selected.regions, record.Region) || !matches(selected.cities, record.City) ||
			!matches(selected.hostnames, record.Hostname) {
			continue
		}
		if len(selected.hostnames) == 0 && slices.Contains(record.Categories, "Dedicated IP") {
			continue
		}
		if !hostnamePattern.MatchString(record.Hostname) || !validKey(record.Key) || strings.TrimSpace(record.Country) == "" {
			return nil, errors.New("matching WireGuard record has an invalid hostname, public key or country")
		}
		for _, value := range record.IPAddresses {
			address, err := netip.ParseAddr(value)
			if err != nil || !address.Is4() || address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
				continue
			}
			countries[strings.ToLower(record.Country)] = true
			id := struct {
				address netip.Addr
				key     string
			}{address, record.Key}
			if !seen[id] {
				peers = append(peers, peer{record.Hostname, record.Country, address, record.Key})
				seen[id] = true
			}
		}
	}
	if len(peers) == 0 {
		return nil, errors.New("no IPv4 NordVPN WireGuard endpoint matches the configured selectors")
	}
	if len(countries) != 1 {
		return nil, errors.New("matched WireGuard endpoints span multiple countries; narrow the selectors")
	}
	if len(selected.hostnames) > 0 {
		// Honor an operator's preferred host order, then retain snapshot IP order.
		order := func(hostname string) int {
			return slices.IndexFunc(selected.hostnames, func(value string) bool {
				return strings.EqualFold(value, hostname)
			})
		}
		slices.SortStableFunc(peers, func(a, b peer) int {
			return order(a.Hostname) - order(b.Hostname)
		})
	}
	return peers, nil
}
