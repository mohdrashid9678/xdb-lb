package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  bpf ../../bpf/xdp.c -- -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const RingSize = 251

type Engine struct {
	objs bpfObjects
	link link.Link
}

func NewEngine(backends []string) (*Engine, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	engine := &Engine{objs: objs}
	if err := engine.populateMaps(backends); err != nil {
		objs.Close()
		return nil, err
	}

	return engine, nil
}

func (e *Engine) Attach(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup interface: %w", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   e.objs.XdpLoadBalancer,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attach XDP: %w", err)
	}

	e.link = l
	return nil
}

func (e *Engine) Close() {
	if e.link != nil {
		e.link.Close()
	}
	e.objs.Close()
}

// GetStatsMap exposes the map for the telemetry package to read safely
func (e *Engine) GetStatsMap() *ebpf.Map {
	return e.objs.BackendStats
}

func (e *Engine) populateMaps(backends []string) error {
	numBackends := uint32(len(backends))
	
	// Populate physical IPs
	for i, ipStr := range backends {
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			return fmt.Errorf("invalid IP: %s", ipStr)
		}
		ipUint := binary.LittleEndian.Uint32(ip)
		
		if err := e.objs.Backends.Put(uint32(i), ipUint); err != nil {
			return err
		}
	}

	// Populate Consistent Hashing Ring 
	for i := uint32(0); i < RingSize; i++ {
		backendID := i % numBackends
		if err := e.objs.ChRing.Put(i, backendID); err != nil {
			return err
		}
	}
	return nil
}