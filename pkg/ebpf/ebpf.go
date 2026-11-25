// Package ebpf loads the XDP data plane into the kernel and programs its maps.
package ebpf

// -Wall -Werror are passed here, after the "--", because that is the only
// place bpf2go forwards flags to clang from. A warning in the data plane is a
// build failure.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../../bpf/xdp.c -- -Wall -Werror -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Options are load-time settings baked into the program before verification.
type Options struct {
	// Debug enables per-packet bpf_printk tracing. It is very slow and writes
	// to the system-wide trace pipe; never enable it under real load.
	Debug bool
}

type Engine struct {
	objs bpfObjects
	link link.Link
}

func NewEngine(backends []netip.Addr, opts Options) (*Engine, error) {
	if len(backends) == 0 {
		return nil, errors.New("no backends")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// Load the spec (the parsed ELF) rather than the objects directly, so we
	// can inspect and rewrite it before anything is sent to the kernel.
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}

	// Map sizes come from the compiled object (bpf/maps.h), not from Go
	// constants, so C and Go cannot disagree.
	if max := spec.Maps["backends"].MaxEntries; uint32(len(backends)) > max {
		return nil, fmt.Errorf("%d backends configured, but the data plane supports at most %d (MAX_BACKENDS in bpf/maps.h)", len(backends), max)
	}

	// Rewrite the .rodata constant before load. The kernel freezes .rodata,
	// so the verifier sees a known value and deletes the untaken branch.
	var debug uint8
	if opts.Debug {
		debug = 1
	}
	if err := spec.Variables["debug_enabled"].Set(debug); err != nil {
		return nil, fmt.Errorf("set debug_enabled: %w", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		// A VerifierError carries the full verifier log; %+v prints it.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load bpf objects: %+v", ve)
		}
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

func (e *Engine) populateMaps(backends []netip.Addr) error {
	// Backend IPs. The value is written as four raw bytes, which is already
	// network byte order, the same layout the data plane sees in iphdr. Going
	// through a uint32 would make the result depend on host endianness.
	for i, addr := range backends {
		if err := e.objs.Backends.Put(uint32(i), addr.As4()); err != nil {
			return fmt.Errorf("write backend %d (%s): %w", i, addr, err)
		}
	}

	// Ring. Still slot % N: simple and even, but not consistent (changing N
	// remaps most slots). Replaced by Maglev in phase 3.
	numBackends := uint32(len(backends))
	ringSize := e.objs.ChRing.MaxEntries()
	for i := uint32(0); i < ringSize; i++ {
		if err := e.objs.ChRing.Put(i, i%numBackends); err != nil {
			return fmt.Errorf("write ring slot %d: %w", i, err)
		}
	}
	return nil
}
