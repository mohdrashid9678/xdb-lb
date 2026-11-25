package main

import (
	"context"
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

const statsInterval = 3 * time.Second

func main() {
	configPath := flag.String("config", "config.json", "path to the JSON configuration file")
	debug := flag.Bool("debug", false, "trace every packet to the kernel trace pipe (slow)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *configPath, *debug); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, configPath string, debug bool) (err error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	engine, err := ebpf.NewEngine(cfg.Backends, ebpf.Options{Debug: debug})
	if err != nil {
		return fmt.Errorf("initialize eBPF engine: %w", err)
	}
	defer func() {
		if closeErr := engine.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("detach: %w", closeErr)
		}
	}()

	if err := engine.Attach(cfg.Interface); err != nil {
		return fmt.Errorf("attach to interface %s: %w", cfg.Interface, err)
	}
	log.Printf("XDP L4 Balancer attached to %s", cfg.Interface)
	log.Printf("Hashing TCP flows across %d backends", len(cfg.Backends))

	telemetry.Run(ctx, engine, cfg.Backends, statsInterval)

	log.Println("Detaching XDP program and shutting down...")
	return nil
}
