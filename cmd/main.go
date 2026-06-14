package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  bpf ../bpf/xdp.c -- -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load pre-compiled programs into the kernel.
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Hardcoded for testing. You will make this configurable via flags later.
	ifaceName := "eth1" 
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to find network interface %q: %s", ifaceName, err)
	}

	// Attach the program to the XDP hook
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("XDP Load Balancer attached to %s", ifaceName)
	log.Println("Press CTRL+C to detach and exit.")

	// Graceful shutdown
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("Detaching XDP program...")
}