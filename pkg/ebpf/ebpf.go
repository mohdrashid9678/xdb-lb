// Package ebpf loads the XDP data plane and programs its maps.
package ebpf

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

// Options are fixed for the lifetime of the loaded program.
type Options struct {
	// Debug traces every packet to the kernel trace pipe.
	Debug bool
}

type Engine struct {
	objs     bpfObjects
	link     link.Link
	backends int
}

func NewEngine(backends []netip.Addr, opts Options) (*Engine, error) {
	if len(backends) == 0 {
		return nil, errors.New("no backends")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := loadSpec(opts)
	if err != nil {
		return nil, err
	}
	if max := spec.Maps["backends"].MaxEntries; uint32(len(backends)) > max {
		return nil, fmt.Errorf("%d backends configured, at most %d supported", len(backends), max)
	}

	e := &Engine{backends: len(backends)}
	if err := spec.LoadAndAssign(&e.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load bpf objects: %+v", ve)
		}
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	if err := e.populateMaps(backends); err != nil {
		e.objs.Close()
		return nil, err
	}
	return e, nil
}

func loadSpec(opts Options) (*ebpf.CollectionSpec, error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}

	var debug uint8
	if opts.Debug {
		debug = 1
	}
	if err := spec.Variables["debug_enabled"].Set(debug); err != nil {
		return nil, fmt.Errorf("set debug_enabled: %w", err)
	}
	return spec, nil
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

// Close detaches the program and releases its maps.
func (e *Engine) Close() error {
	var linkErr error
	if e.link != nil {
		linkErr = e.link.Close()
	}
	return errors.Join(linkErr, e.objs.Close())
}

// PacketCounts returns the packets seen per backend, in config order.
func (e *Engine) PacketCounts() ([]uint64, error) {
	counts := make([]uint64, e.backends)
	for i := range counts {
		if err := e.objs.BackendStats.Lookup(uint32(i), &counts[i]); err != nil {
			return nil, fmt.Errorf("read counter %d: %w", i, err)
		}
	}
	return counts, nil
}

func (e *Engine) populateMaps(backends []netip.Addr) error {
	// As4 is already in network byte order, matching iphdr in the data plane.
	for i, addr := range backends {
		if err := e.objs.Backends.Put(uint32(i), addr.As4()); err != nil {
			return fmt.Errorf("write backend %d (%s): %w", i, addr, err)
		}
	}

	n := uint32(len(backends))
	for slot := uint32(0); slot < e.objs.ChRing.MaxEntries(); slot++ {
		if err := e.objs.ChRing.Put(slot, slot%n); err != nil {
			return fmt.Errorf("write ring slot %d: %w", slot, err)
		}
	}
	return nil
}
