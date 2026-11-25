package ebpf

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

var testBackends = []netip.Addr{
	netip.MustParseAddr("192.168.1.100"),
	netip.MustParseAddr("192.168.1.101"),
	netip.MustParseAddr("192.168.1.102"),
}

// tcpSYN builds a minimal Ethernet/IPv4/TCP frame.
func tcpSYN() []byte {
	const ethLen, ipLen, tcpLen = 14, 20, 20
	pkt := make([]byte, ethLen+ipLen+tcpLen)

	binary.BigEndian.PutUint16(pkt[12:], 0x0800)

	ip := pkt[ethLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], ipLen+tcpLen)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:], netip.MustParseAddr("10.0.0.2").AsSlice())
	copy(ip[16:], netip.MustParseAddr("10.0.0.1").AsSlice())

	tcp := ip[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:], 55555)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	return pkt
}

func newTestEngine(tb testing.TB, opts Options) *Engine {
	tb.Helper()
	e, err := NewEngine(testBackends, opts)
	if errors.Is(err, os.ErrPermission) {
		tb.Skip("loading eBPF programs requires root")
	}
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { e.Close() })
	return e
}

// BenchmarkDataPlane measures the per-packet cost of the XDP program using
// BPF_PROG_TEST_RUN: the kernel runs the loaded program b.N times on one frame.
func BenchmarkDataPlane(b *testing.B) {
	modes := []struct {
		name string
		opts Options
	}{
		{"tracing=off", Options{}},
		{"tracing=on", Options{Debug: true}},
	}

	for _, mode := range modes {
		b.Run(mode.name, func(b *testing.B) {
			e := newTestEngine(b, mode.opts)
			prog := e.objs.XdpLoadBalancer
			pkt := tcpSYN()

			b.ResetTimer()
			verdict, err := prog.Run(&ebpf.RunOptions{Data: pkt, Repeat: uint32(b.N)})
			b.StopTimer()

			if err != nil {
				b.Fatal(err)
			}
			const xdpPass = 2
			if verdict != xdpPass {
				b.Fatalf("verdict = %d, want XDP_PASS", verdict)
			}
			assertCounted(b, e, uint64(b.N))
			b.ReportMetric(float64(instructionCount(b, prog)), "insns")
		})
	}
}

func assertCounted(tb testing.TB, e *Engine, want uint64) {
	tb.Helper()
	counts, err := e.PacketCounts()
	if err != nil {
		tb.Fatal(err)
	}
	var total uint64
	for _, c := range counts {
		total += c
	}
	if total != want {
		tb.Fatalf("counted %d packets, want %d", total, want)
	}
}

func instructionCount(tb testing.TB, prog *ebpf.Program) int {
	tb.Helper()
	info, err := prog.Info()
	if err != nil {
		tb.Fatal(err)
	}
	insns, err := info.Instructions()
	if err != nil {
		tb.Fatal(err)
	}
	return len(insns)
}
