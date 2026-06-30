package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/mohdrashid9678/xdb-lb/pkg/config"
	"github.com/mohdrashid9678/xdb-lb/pkg/ebpf"
	"github.com/mohdrashid9678/xdb-lb/pkg/telemetry"
)

func main() {
	// Load Configuration
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Backends) == 0 {
		log.Fatalf("No backends defined in configuration")
	}

	// Initialize eBPF Engine
	engine, err := ebpf.NewEngine(cfg.Backends)
	if err != nil {
		log.Fatalf("Failed to initialize eBPF engine: %v", err)
	}
	defer engine.Close()

	// Attach to Network Interface
	if err := engine.Attach(cfg.Interface); err != nil {
		log.Fatalf("Failed to attach to interface %s: %v", cfg.Interface, err)
	}
	log.Printf("XDP L4 Balancer attached to %s", cfg.Interface)
	log.Printf("Routing traffic across %d backends via Consistent Hashing", len(cfg.Backends))

	// Start Telemetry
	telemetry.StartPolling(engine.GetStatsMap(), cfg.Backends, 3*time.Second)

	// Wait for Shutdown Signal
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("Detaching XDP program and shutting down...")
}