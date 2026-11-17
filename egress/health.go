package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	probeInterval    = 10 * time.Second
	probeTimeout     = 4 * time.Second
	handshakeMaxAge  = 180 * time.Second
	statusMaxAge     = 30 * time.Second
	failureThreshold = 3
	successThreshold = 2
	maxBackoff       = 60 * time.Second
	statusFile       = "/run/nordvpn-egress-status.json"
)

type measurement struct {
	Handshake time.Time
	ProxyOK   bool
	DNSOK     bool
}

func (m measurement) reason(now time.Time) string {
	if m.Handshake.IsZero() || now.Sub(m.Handshake) > handshakeMaxAge {
		return "handshake"
	}
	if !m.ProxyOK {
		return "proxy_egress"
	}
	if !m.DNSOK {
		return "dns"
	}
	return ""
}

func probe(ctx context.Context, cfg config) measurement {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(&url.URL{Scheme: "socks5h", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))}),
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	type result struct {
		kind string
		ok   bool
	}
	count := len(cfg.IPProbes) + len(cfg.NameProbes) + len(cfg.DNS)
	results := make(chan result, count)
	for kind, targets := range map[string][]string{"ip": cfg.IPProbes, "name": cfg.NameProbes} {
		for _, target := range targets {
			go func() {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					results <- result{kind, false}
					return
				}
				response, err := client.Do(request)
				if err != nil {
					results <- result{kind, false}
					return
				}
				response.Body.Close()
				results <- result{kind, response.StatusCode >= 200 && response.StatusCode < 300}
			}()
		}
	}
	for _, server := range cfg.DNS {
		go func() {
			resolver := net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
				},
			}
			_, err := resolver.LookupNetIP(ctx, "ip4", "example.com.")
			results <- result{"dns", err == nil}
		}()
	}

	var measurement measurement
	for i := 0; i < count; i++ {
		result := <-results
		if result.ok {
			measurement.ProxyOK = measurement.ProxyOK || result.kind == "ip" || result.kind == "name"
			measurement.DNSOK = measurement.DNSOK || result.kind == "dns" || result.kind == "name"
		}
	}
	return measurement
}

type healthState struct {
	State         string     `json:"state"`
	Ready         bool       `json:"ready"`
	Endpoint      string     `json:"endpoint"`
	EndpointIP    string     `json:"endpoint_ip"`
	Country       string     `json:"country"`
	HandshakeAt   *time.Time `json:"handshake_at,omitempty"`
	ProxyOK       bool       `json:"proxy_ok"`
	DNSOK         bool       `json:"dns_ok"`
	Failures      int        `json:"consecutive_failures"`
	LastCheckedAt time.Time  `json:"last_checked_at"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	Reason        string     `json:"reason,omitempty"`
	SwitchCount   int        `json:"switch_count"`
}

type recovery struct {
	healthState
	successes  int
	attempts   int
	nextSwitch time.Time
	backoff    time.Duration
}

func (r *recovery) observe(now time.Time, m measurement, peerCount int) bool {
	r.LastCheckedAt = now
	r.HandshakeAt = nil
	if !m.Handshake.IsZero() {
		r.HandshakeAt = &m.Handshake
	}
	r.ProxyOK, r.DNSOK, r.Reason = m.ProxyOK, m.DNSOK, m.reason(now)
	if r.Reason == "" {
		r.successes++
		r.Failures = 0
		r.LastSuccessAt = &now
		r.nextSwitch = time.Time{}
		if r.successes >= successThreshold {
			r.Ready, r.State = true, "healthy"
			r.attempts, r.backoff = 0, 0
		}
		return false
	}
	r.successes = 0
	r.Failures++
	if r.Failures < failureThreshold {
		return false
	}
	r.Ready, r.State = false, "unhealthy"

	if r.attempts+1 >= peerCount {
		if r.nextSwitch.IsZero() {
			r.backoff = min(max(r.backoff*2, probeInterval), maxBackoff)
			r.nextSwitch = now.Add(r.backoff)
		}
		if now.Before(r.nextSwitch) {
			return false
		}
		r.attempts = 0
	} else {
		r.attempts++
	}
	r.nextSwitch = time.Time{}
	return true
}

func (r *recovery) activated(now time.Time, active peer) {
	r.State, r.Ready = "starting", false
	r.Endpoint, r.EndpointIP, r.Country = active.Hostname, active.IP.String(), active.Country
	r.HandshakeAt, r.ProxyOK, r.DNSOK = nil, false, false
	r.Failures, r.successes = 0, 0
	r.LastCheckedAt = now
}

func writeStatus(s healthState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := statusFile + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, statusFile)
}

func readStatus() ([]byte, healthState, error) {
	var status healthState
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return nil, status, errors.New("egress status is not available")
	}
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, status, errors.New("invalid egress status")
	}
	if time.Since(status.LastCheckedAt) > statusMaxAge {
		return nil, status, errors.New("egress status is stale")
	}
	return data, status, nil
}
