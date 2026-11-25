# Project notes: roadmap, concepts and decisions

The goal of this project is to find the limits of a Layer 4 load balancer:
forward real traffic correctly, then extract every bit of per-packet
performance, and measure each step so claims are backed by numbers.

The work is done in phases, one pull request per phase. Each phase has a note
in this directory recording **what we learned, the concepts involved and the
decisions taken**, so the reasoning survives alongside the code.

| Phase | Goal | Status | Notes |
| --- | --- | --- | --- |
| 0. Clean up | Honest README, strict build, validated config, tracing off by default | Done | [phase-0-cleanup.md](phase-0-cleanup.md) |
| 1. Safety net | Packet-level tests, per-packet benchmarks, CI, flags | Planned | |
| 2. Balance for real | Virtual services, MAC rewrite + `XDP_TX`, one-command demo | Planned | |
| 3. Balance well | Maglev hashing with weights, LRU connection table, health checks, live reload | Planned | |
| 4. Operate it | Per-CPU metrics + Prometheus, pinned maps and hitless restart, packaging | Planned | |
| 5. Extend | IPIP, IPv6, UDP, VLAN, published benchmark against IPVS | Planned | |

## How we measure

Performance work without measurement is guessing, so every phase reports
numbers from the same ladder, cheapest first:

1. **Instruction count** of the loaded program (after verifier dead-code
   elimination). Free, deterministic, catches accidental bloat.
2. **Nanoseconds per packet** via `BPF_PROG_TEST_RUN` (`Program.Benchmark` in
   `cilium/ebpf`). Runs the real program in the kernel on a crafted packet,
   with no NIC involved. Good for comparing two versions of the code; it does
   not include driver, cache-miss or multi-core effects.
3. **Packets per second on real interfaces** (veth first, then physical NICs
   with a traffic generator). The only number that counts as throughput.

Numbers from step 2 taken inside a VM are only meaningful relative to each
other on the same machine and run.
