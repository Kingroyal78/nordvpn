package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const proxyUID = 10001

func writeProxyConfig(dir string, filename string, options map[string]any) (string, error) {
	path := filepath.Join(dir, filename)
	data, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}
	return path, os.Chown(path, proxyUID, proxyUID)
}

func run(ctx context.Context, cfg config, log *slog.Logger) error {
	if err := configureNetwork(ctx, cfg); err != nil {
		return err
	}
	active := 0
	if err := activatePeer(ctx, nil, cfg.Peers[active], cfg.PeerPort); err != nil {
		return fmt.Errorf("activate first endpoint: %w", err)
	}

	dir, err := os.MkdirTemp("/run", "nordvpn-egress-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0711); err != nil {
		return err
	}
	serverConfig, err := writeProxyConfig(dir, "server.json", map[string]any{
		"server": "0.0.0.0", "server_port": cfg.SSPort, "password": cfg.Password,
		"method": defaultCipher, "mode": "tcp_and_udp", "dns": strings.Join(cfg.DNS, ","),
		"dns_cache_size": 0,
	})
	if err != nil {
		return err
	}
	clientConfig, err := writeProxyConfig(dir, "client.json", map[string]any{
		"server": "127.0.0.1", "server_port": cfg.SSPort, "password": cfg.Password,
		"method": defaultCipher, "local_address": "127.0.0.1", "local_port": proxyPort,
	})
	if err != nil {
		return err
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	var children sync.WaitGroup
	defer func() {
		cancel()
		children.Wait()
	}()
	exited := make(chan error, 2)
	for process, path := range map[string]string{"ssserver": serverConfig, "sslocal": clientConfig} {
		cmd := exec.CommandContext(proxyCtx, process, "-c", path)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: proxyUID, Gid: proxyUID}}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start %s: %w", process, err)
		}
		children.Go(func() {
			// Never relay the proxy's config parsing or client traffic logs.
			exited <- fmt.Errorf("%s exited (%v)", process, cmd.Wait())
		})
	}

	var recovery recovery
	recovery.activated(time.Now(), cfg.Peers[active])
	if err := writeStatus(recovery.healthState); err != nil {
		return err
	}
	defer os.Remove(statusFile)
	log.Info("WireGuard endpoint selected", "endpoint", recovery.Endpoint, "ip", recovery.EndpointIP, "candidates", len(cfg.Peers))
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-exited:
			if ctx.Err() != nil {
				return nil
			}
			return err
		case <-ticker.C:
			previousState, previousReason := recovery.State, recovery.Reason
			m := probe(ctx, cfg)
			m.Handshake = latestHandshake(ctx)
			switchPeer := recovery.observe(time.Now(), m, len(cfg.Peers))
			if err := writeStatus(recovery.healthState); err != nil {
				return err
			}
			if recovery.State != previousState || recovery.Reason != previousReason {
				log.Info("egress status changed", "state", recovery.State, "endpoint", recovery.Endpoint,
					"reason", recovery.Reason, "failures", recovery.Failures, "last_success_at", recovery.LastSuccessAt)
			}
			if switchPeer && ctx.Err() == nil {
				next := (active + 1) % len(cfg.Peers)
				log.Warn("switching WireGuard endpoint", "from", cfg.Peers[active].Hostname,
					"to", cfg.Peers[next].Hostname, "reason", recovery.Reason, "failures", recovery.Failures,
					"last_success_at", recovery.LastSuccessAt)
				if err := activatePeer(ctx, &cfg.Peers[active], cfg.Peers[next], cfg.PeerPort); err != nil {
					return fmt.Errorf("switch WireGuard endpoint: %w", err)
				}
				active = next
				recovery.SwitchCount++
				recovery.activated(time.Now(), cfg.Peers[active])
				if err := writeStatus(recovery.healthState); err != nil {
					return err
				}
			}
		}
	}
}

func entrypoint(ctx context.Context, args []string, log *slog.Logger) error {
	if len(args) == 0 {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return run(ctx, cfg, log)
	}
	if len(args) != 1 {
		return errors.New("usage: nordvpn-egress [check-config|status|healthcheck]")
	}
	switch args[0] {
	case "check-config":
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"country": cfg.Peers[0].Country, "candidates": len(cfg.Peers), "port": cfg.SSPort,
		})
	case "status", "healthcheck":
		data, status, err := readStatus()
		if err != nil {
			return err
		}
		if args[0] == "status" {
			_, err := os.Stdout.Write(data)
			return err
		}
		if !status.Ready {
			return fmt.Errorf("egress %s (%s)", status.State, status.Reason)
		}
		return nil
	default:
		return errors.New("usage: nordvpn-egress [check-config|status|healthcheck]")
	}
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := entrypoint(ctx, os.Args[1:], log); err != nil {
		log.Error("egress command failed", "error", err)
		os.Exit(1)
	}
}
