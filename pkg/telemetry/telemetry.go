package telemetry

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
)

func StartPolling(statsMap *ebpf.Map, backends []string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			log.Println("--- Live TCP Traffic Telemetry ---")
			for i, ipStr := range backends {
				var count uint64
				err := statsMap.Lookup(uint32(i), &count)
				if err != nil {
					continue
				}
				log.Printf("Backend [%s]: %d packets routed\n", ipStr, count)
			}
		}
	}()
}