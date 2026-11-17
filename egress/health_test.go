package main

import (
	"testing"
	"time"
)

func TestRecoveryThresholds(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	ok := measurement{Handshake: now, ProxyOK: true, DNSOK: true}
	bad := measurement{Handshake: now, DNSOK: true}
	r := recovery{}
	for round, m := range []measurement{ok, ok, bad, bad, ok, bad, bad, bad} {
		switched := r.observe(now.Add(time.Duration(round)*probeInterval), m, 2)
		if switched != (round == 7) || r.Ready != (round >= 1 && round < 7) {
			t.Fatalf("round %d: ready=%t switched=%t reason=%s", round, r.Ready, switched, r.Reason)
		}
	}
	if r.Reason != "proxy_egress" {
		t.Fatalf("expected egress failure with a handshake, got %q", r.Reason)
	}
	r.activated(now.Add(80*time.Second), peer{})
	r.observe(now.Add(90*time.Second), ok, 2)
	if r.Ready {
		t.Fatal("first healthy round after a switch marked egress ready")
	}
	r.observe(now.Add(100*time.Second), ok, 2)
	if !r.Ready || r.attempts != 0 {
		t.Fatal("successful failover did not reset the sweep")
	}
}

func TestExhaustedCandidatesBackOff(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	r := recovery{}
	for _, delay := range []time.Duration{10, 20, 40, 60, 60} {
		for i := 0; i < failureThreshold; i++ {
			if r.observe(now, measurement{}, 1) {
				t.Fatal("rotated the only candidate before its cooldown")
			}
			now = now.Add(probeInterval)
		}
		due := now.Add(-probeInterval).Add(delay * time.Second)
		if r.nextSwitch != due || r.observe(due.Add(-time.Second), measurement{}, 1) || !r.observe(due, measurement{}, 1) {
			t.Fatalf("single candidate did not back off for %ds", delay)
		}
		now = due.Add(probeInterval)
		r.activated(now, peer{})
	}
}
