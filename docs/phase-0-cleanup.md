# Phase 0: clean up

**Goal:** make the repository honest and tidy before building on it. No new
load-balancing behaviour; the packet path is unchanged except that tracing is
off by default.

## What changed

| Area | Before | After |
| --- | --- | --- |
| Per-packet tracing | `bpf_printk` on every packet, always | Off by default; `-debug` turns it on |
| Build strictness | `-Wall -Werror` declared in the Makefile but never passed to clang | Passed on the `go:generate` line; a warning fails the build |
| Config | Errors surfaced one at a time, some as raw kernel errors | Every problem reported at once, before the kernel is touched |
| Map sizes | `251` and `10` repeated in C and Go | Defined once in `bpf/maps.h`; Go reads them from the compiled object |
| Backend IP encoding | Packed with `binary.LittleEndian` | Written as four raw bytes; no host-endianness dependency |
| CLI | Config path fixed to `./config.json`, no `--help` | `-config`, `-debug`, working `--help` |
| Shutdown | `log.Fatal` paths skipped deferred cleanup | `run()` returns errors so `engine.Close()` always runs |
| Telemetry | Read the raw eBPF map from a goroutine that never stopped | Depends on a one-method `Source` interface and stops on shutdown |
| Go hygiene | Unformatted, `go.mod` out of date | `gofmt` clean, `go mod tidy` clean, first unit tests |
| README | Claimed load balancing; invalid `nc -p 66666`; no teardown | Status stated up front; working demo; teardown; requirements; config reference |

## Concepts

### Where XDP runs, and why every instruction matters
An XDP program runs in the NIC driver's receive path, before the kernel
allocates an `sk_buff` for the packet. That is where its speed comes from: a
packet can be dropped, rewritten or bounced back out without paying for the
network stack. The flip side is that the program runs once per packet on the
hottest path in the system. At 10 million packets per second a core has 100 ns
per packet in total, so a single helper call that costs hundreds of
nanoseconds decides the outcome on its own.

### Load-time constants and verifier dead-code elimination
Globals declared `volatile const` are placed in the object's `.rodata`
section. The loader turns `.rodata` into an array map, writes the values, and
**freezes** it before the program is verified. Because the map can no longer
change, the verifier treats reads from it as known constants, proves which
side of a branch can never run, and deletes that code from the program.

This gives a feature flag with zero runtime cost: one binary, two behaviours,
chosen at load time. `debug_enabled` is the first use; later phases will use
the same mechanism for anything that is fixed for the lifetime of the program
(for example a hash seed or feature switches).

`volatile` is needed only so clang does not fold the default value (`0`) at
compile time and delete the block before the loader gets a chance to change it.

### Why `bpf_printk` is so expensive
`bpf_printk` formats a string in the kernel and writes it as an event into
the system-wide trace buffer. It is a debugging tool. On every packet it
both dominates the per-packet cost (see the measurement below) and floods a
buffer that every other tracing tool on the host shares.

### Byte order
Packet headers are big-endian ("network order"). The data plane compares and
hashes addresses exactly as they appear in the packet, with no byte swap.
The control plane therefore stores backend addresses as the same four raw
bytes. Converting through a `uint32` in Go makes the stored bytes depend on
the host's endianness; writing a `[4]byte` does not.

## Decisions

1. **Keep the trace code, gate it with a `.rodata` constant.** Alternatives
   were deleting it (loses a useful debugging aid) or a runtime map lookup
   (costs a lookup per packet forever). The constant costs nothing when off.
2. **Compiler flags live on the `go:generate` line, not in the Makefile.**
   `bpf2go` only forwards flags given after `--` (or via `-cflags`), so the
   Makefile variables were never applied. Keeping them in one place means
   `go generate` and `make` cannot disagree.
3. **Validate configuration in Go before loading anything.** `config.Parse`
   is pure (bytes in, typed config out), so it is unit-testable and runs
   first. Backends are parsed once into `netip.Addr`; nothing downstream
   handles strings. The capacity check needs the compiled object, so it sits in the
   engine and reads `MAX_BACKENDS` from the map spec.
4. **Reject unknown config keys.** A typo such as `"backend"` used to be
   ignored silently and resurface as "no backends defined".
5. **`interface: "auto"` is kept but discouraged.** It attaches to whatever
   carries the default route, usually the primary NIC. Phase 1 makes the
   interface explicit on the command line.
6. **Minimal flags now, full CLI in phase 1.** `-debug` needed a flag, and Go's
   `flag` package gives `--help` for free. `--interface`, `--xdp-mode`,
   `--stats-interval` and `--version` come with phase 1.
7. **Telemetry depends on an interface, not on the eBPF map.** The engine
   exposes `PacketCounts()`; telemetry accepts anything with that method.
   The map layout can change (per-CPU counters in phase 4) without touching
   the reporting code, and the reporter can be tested with a fake.
8. **The ring stays `slot % N` for now.** It is not consistent hashing, and
   the README no longer says it is. It is replaced by Maglev in phase 3, after
   forwarding exists and there is something to measure it against.

## Learnings

- **The unused-variable warning was real and hidden.** Compiling `bpf/xdp.c`
  with `-Wall -Werror` failed on `src_ip`; the build only passed because the
  flags never reached clang.
- **Tracing cost about 20x the rest of the program.** Measured with
  `BPF_PROG_TEST_RUN` (2,000,000 runs, 3 rounds each, one 54-byte TCP SYN):

  | Build | Loaded instructions | Per packet |
  | --- | --- | --- |
  | Tracing off (default) | 115 | 16 to 20 ns |
  | Tracing on (`-debug`) | 131 | 411 to 423 ns |

  The instruction counts confirm the verifier removed the tracing block:
  the same object file loads as 115 instructions with the flag off and 131
  with it on. These were taken in a cloud VM, so read them as a ratio, not as
  absolute throughput.
- **`go build` cannot work from a fresh clone** because the generated
  bindings are git-ignored and need clang. That is acceptable for now and is
  revisited with packaging in phase 4.

## How it was verified

- `make` from a clean tree, `gofmt -l .`, `go vet ./...`, `go mod tidy -diff`: clean.
- `clang -Wall -Werror -target bpf` on `bpf/xdp.c`: clean.
- `go test ./...`: config validation and loading tests pass.
- Ran the binary on loopback with 3 backends: 60 connection attempts produced
  120 counted packets across the three; SIGTERM detached cleanly.
- Error paths: mixed invalid config (3 problems listed together), 11 backends,
  missing interface, missing file, `--help`.
- Read the backend map back from the kernel: `192.168.1.101` is stored as
  bytes `192 168 1 101`.

## Not done here (on purpose)

No change to forwarding, hashing quality, counters or the testbed. Those
belong to phases 1 to 4 and each gets its own measurements.
