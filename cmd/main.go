package main

import (
	"flag"
	"fmt"
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
	configPath := flag.String("config", "config.json", "path to the JSON configuration file")
	debug := flag.Bool("debug", false, "trace every packet to /sys/kernel/debug/tracing/trace_pipe (slow; never use under load)")
	flag.Parse()

	if err := run(*configPath, *debug); err != nil {
		log.Fatal(err)
	}
}

// run holds the program's lifetime so that deferred cleanup (detaching the
// XDP program) always executes; log.Fatal in main would skip it.
func run(configPath string, debug bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	backends := cfg.BackendAddrs()

	engine, err := ebpf.NewEngine(backends, ebpf.Options{Debug: debug})
	if err != nil {
		return fmt.Errorf("initialize eBPF engine: %w", err)
	}
	defer engine.Close()

	if err := engine.Attach(cfg.Interface); err != nil {
		return fmt.Errorf("attach to interface %s: %w", cfg.Interface, err)
	}
	log.Printf("XDP L4 Balancer attached to %s", cfg.Interface)
	log.Printf("Hashing TCP flows across %d backends", len(backends))
	if debug {
		log.Printf("Debug tracing ON: per-packet output in /sys/kernel/debug/tracing/trace_pipe")
	}

	telemetry.StartPolling(engine.GetStatsMap(), backends, 3*time.Second)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("Detaching XDP program and shutting down...")
	return nil
}
