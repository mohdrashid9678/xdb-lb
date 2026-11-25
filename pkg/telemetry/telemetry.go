// Package telemetry reports per-backend traffic counters.
package telemetry

import (
	"context"
	"log"
	"net/netip"
	"time"
)

// Source provides the packets seen per backend, in the order of the backend list.
type Source interface {
	PacketCounts() ([]uint64, error)
}

// Run logs the counters every interval until ctx is cancelled.
func Run(ctx context.Context, src Source, backends []netip.Addr, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report(src, backends)
		}
	}
}

func report(src Source, backends []netip.Addr) {
	counts, err := src.PacketCounts()
	if err != nil {
		log.Printf("telemetry: %v", err)
		return
	}

	log.Println("--- Live TCP Traffic Telemetry ---")
	for i, addr := range backends {
		log.Printf("Backend [%s]: %d packets routed", addr, counts[i])
	}
}
