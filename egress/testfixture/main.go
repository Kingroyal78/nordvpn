// Command testfixture serves deterministic HTTP and DNS inside the CI test peers.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
)

func dnsReply(query []byte, address netip.Addr) []byte {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil
	}
	offset := 12
	for offset < len(query) && query[offset] != 0 {
		offset += int(query[offset]) + 1
	}
	if offset+5 > len(query) {
		return nil
	}
	response := append([]byte(nil), query[:offset+5]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	if binary.BigEndian.Uint16(query[offset+1:offset+3]) == 1 {
		binary.BigEndian.PutUint16(response[6:8], 1)
		response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4)
		response = append(response, address.AsSlice()...)
	}
	return response
}

func serveDNS(address netip.Addr) {
	conn, err := net.ListenPacket("udp4", ":53")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	var query [4096]byte
	for {
		n, from, err := conn.ReadFrom(query[:])
		if err != nil {
			log.Fatal(err)
		}
		if reply := dnsReply(query[:n], address); len(reply) > 0 {
			_, _ = conn.WriteTo(reply, from)
		}
	}
}

func main() {
	tunnel := netip.MustParseAddr("10.5.0.1")
	peer := os.Getenv("PEER_NAME")
	go serveDNS(tunnel)
	http.HandleFunc("/which", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprint(w, peer+" "+host)
	})
	http.HandleFunc("/probe", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := os.Stat("/tmp/block-proxy"); err == nil {
			http.Error(w, "injected proxy egress failure", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}
