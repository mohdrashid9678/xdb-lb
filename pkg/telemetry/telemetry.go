// Package telemetry reports per-backend counters read from the data plane.
package telemetry

import (
	"log"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
)

// StartPolling logs the per-backend packet counters every interval.
func StartPolling(statsMap *ebpf.Map, backends []netip.Addr, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			log.Println("--- Live TCP Traffic Telemetry ---")
			for i, addr := range backends {
				var count uint64
				if err := statsMap.Lookup(uint32(i), &count); err != nil {
					log.Printf("Backend [%s]: read counter: %v", addr, err)
					continue
				}
				log.Printf("Backend [%s]: %d packets routed", addr, count)
			}
		}
	}()
}
