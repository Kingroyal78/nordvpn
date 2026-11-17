package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(octet byte) string {
	data := make([]byte, 32)
	data[0] = octet
	return base64.StdEncoding.EncodeToString(data)
}

func TestSnapshotSelectors(t *testing.T) {
	records := snapshot{Servers: []serverRecord{
		{VPN: "wireguard", Hostname: "jp1.example.net", Country: "Japan", Region: "Asia", City: "Tokyo", IPAddresses: []string{"192.0.2.11", "2001:db8::1"}, Key: testKey(1)},
		{VPN: "wireguard", Hostname: "jp2.example.net", Country: "Japan", Region: "Asia", City: "Tokyo", IPAddresses: []string{"192.0.2.12", "192.0.2.12"}, Key: testKey(2)},
		{VPN: "wireguard", Hostname: "kr1.example.net", Country: "South Korea", Region: "Asia", City: "Seoul", IPAddresses: []string{"192.0.2.21"}, Key: testKey(3)},
		{VPN: "wireguard", Hostname: "jp3.example.net", Country: "Japan", Region: "Asia", City: "Osaka", IPAddresses: []string{"192.0.2.13"}, Key: testKey(4)},
		{VPN: "openvpn", Hostname: "jp4.example.net", Country: "Japan", Region: "Asia", City: "Tokyo", IPAddresses: []string{"192.0.2.14"}},
		{VPN: "wireguard", Hostname: "jp5.example.net", Country: "Japan", Region: "Asia", City: "Tokyo", Categories: []string{"Dedicated IP"}, IPAddresses: []string{"192.0.2.15"}, Key: testKey(5)},
	}}
	for name, value := range map[string]any{"provider": records, "legacy": map[string]snapshot{"nordvpn": records}} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			peers, err := parsePeers(raw, selection{
				countries: []string{"japan"}, cities: []string{"tokyo"},
				hostnames: []string{"jp2.example.net", "JP1.EXAMPLE.NET", "jp3.example.net"},
			})
			if err != nil || len(peers) != 2 || peers[0].Hostname != "jp2.example.net" || peers[1].Hostname != "jp1.example.net" {
				t.Fatalf("unexpected candidate selection: count=%d err=%v", len(peers), err)
			}
			if _, err := parsePeers(raw, selection{cities: []string{"Kyoto"}}); err == nil {
				t.Fatal("empty selector result accepted")
			}
			if _, err := parsePeers(raw, selection{regions: []string{"Asia"}}); err == nil {
				t.Fatal("cross-country failover accepted")
			}
			peers, err = parsePeers(raw, selection{cities: []string{"Tokyo"}})
			if err != nil || len(peers) != 2 {
				t.Fatalf("ordinary selector must exclude Dedicated IP servers: count=%d err=%v", len(peers), err)
			}
		})
	}
}

func TestSecretInputs(t *testing.T) {
	const name = "TEST_CREDENTIAL"
	path := filepath.Join(t.TempDir(), "secret")
	value := " test password with spaces "
	if err := os.WriteFile(path, []byte(value+"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(name, "")
	t.Setenv(name+"_SECRETFILE", path)
	if got, err := secret(name); err != nil || got != value {
		t.Fatal("file secret did not round-trip")
	}
	t.Setenv(name, value)
	if _, err := secret(name); err == nil || strings.Contains(err.Error(), value) {
		t.Fatal("conflicting secret sources should fail without logging the secret")
	}
}
