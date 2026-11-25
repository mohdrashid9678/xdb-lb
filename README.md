# XDP-LB: High-Performance Layer 4 Load Balancer

XDP-LB is a kernel-level Layer 4 load balancer built on **eBPF** and **XDP (eXpress Data Path)**. Packets are processed inside the Network Interface Card (NIC) driver, before the Linux networking stack allocates any per-packet state, so the per-packet cost is measured in nanoseconds.

## Architecture
The system is divided into two decoupled layers that share state through eBPF maps:

* **The Data Plane (C):** A C program compiled to eBPF bytecode and attached at the XDP hook. It runs in the kernel once per received packet.
* **The Control Plane (Go):** A user-space daemon built with `cilium/ebpf`. It validates the configuration, loads the program, programs the maps and reports telemetry.

```
 user space                                        kernel
┌──────────────────────────┐              ┌──────────────────────────────┐
│ config.json              │              │  NIC driver (XDP hook)       │
│      │                   │              │        │                     │
│      ▼                   │   writes     │        ▼                     │
│ xdp-lb (Go) ─────────────┼─► ch_ring ───┼─► XDP program                │
│      ▲                   │   backends   │   parse → hash → select      │
│      │       reads       │              │        │                     │
│      └───────────────────┼── backend_stats ◄─────┘ count               │
└──────────────────────────┘              └──────────────────────────────┘
```

### Packet path
For every received frame the data plane:

1. Validates the Ethernet, IPv4 and TCP headers with explicit bounds checks. Truncated frames are dropped; non-IPv4 and non-TCP traffic is passed through untouched.
2. Hashes the 5-Tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol).
3. Maps the hash onto a 251-slot ring (`ch_ring`) to select a backend, so every packet of a connection selects the same backend.
4. Increments that backend's packet counter (`backend_stats`).
5. Returns `XDP_PASS`, handing the packet to the host network stack.

### Maps
| Map | Type | Key → Value | Written by |
| --- | --- | --- | --- |
| `ch_ring` | Array, 251 entries | ring slot → backend ID | Control plane, at start |
| `backends` | Array, 10 entries | backend ID → IPv4 address | Control plane, at start |
| `backend_stats` | Array, 10 entries | backend ID → packet count | Data plane, per packet |

## ✨ Core Features
* **TCP Stickiness:** A 5-Tuple hash against the ring keeps every packet of a TCP connection on the same backend.
* **Kernel-Space to User-Space Telemetry:** Per-backend counters are aggregated in kernel memory and polled asynchronously by Go.
* **Validated Configuration:** Backend pools are read from JSON and checked before anything touches the kernel. Every problem in the file is reported at once.
* **Zero-Cost Debug Tracing:** Per-packet tracing is compiled in, but the verifier removes it from the loaded program unless `-debug` is set.

## Getting Started

### 1. Prerequisites
* Linux kernel **5.9+** (`-debug` tracing needs **5.16+**)
* Go **1.24+**
* clang/LLVM and the libbpf headers

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-generic iproute2 netcat-openbsd
```

### 2. Build
The Makefile compiles the C code to eBPF, generates the Go bindings and builds the daemon.
```bash
make
```

### 3. Configure
`config.json`:
```json
{
    "interface": "veth-host",
    "backends": [
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.102"
    ]
}
```

| Key | Description |
| --- | --- |
| `interface` | Interface to attach to. `"auto"` selects the interface that carries the default route. |
| `backends` | 1 to 10 unique IPv4 addresses. |

### 4. Run
Loading eBPF programs requires root, or `CAP_BPF` and `CAP_NET_ADMIN`.
```bash
sudo ./xdp-lb -config config.json
```

| Flag | Default | Description |
| --- | --- | --- |
| `-config` | `config.json` | Path to the configuration file. |
| `-debug` | `false` | Trace every packet to the kernel trace pipe. Slow; not for use under load. |
| `-h` | | Print usage. |

Stop the daemon with `Ctrl-C`; the XDP program is detached on exit.

## Try It Locally
To test ingress XDP without touching your main connection, create a virtual ethernet (veth) pair and a network namespace:
```bash
sudo ip link add veth-host type veth peer name veth-guest
sudo ip netns add xdp-test
sudo ip link set veth-guest netns xdp-test
sudo ip addr add 10.0.0.1/24 dev veth-host
sudo ip link set veth-host up
sudo ip netns exec xdp-test ip addr add 10.0.0.2/24 dev veth-guest
sudo ip netns exec xdp-test ip link set veth-guest up
sudo ip netns exec xdp-test ip link set lo up
```

Run the daemon with tracing on (Terminal 1):
```bash
sudo ./xdp-lb -config config.json -debug
```
![Screenshot](assets/telemetry.png)

Watch the kernel trace (Terminal 2):
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
![Screenshot](assets/trace.png)

Send traffic from the namespace (Terminal 3). The same source port always selects the same backend:
```bash
# Client A
sudo ip netns exec xdp-test nc -p 55555 -zv 10.0.0.1 80

# Client B
sudo ip netns exec xdp-test nc -p 44444 -zv 10.0.0.1 80
```

Clean up:
```bash
sudo ip netns del xdp-test
sudo ip link del veth-host
```

## Benchmarks
The data plane is benchmarked with `BPF_PROG_TEST_RUN`: the kernel executes the loaded program repeatedly on a 54-byte TCP SYN and reports the time per run. This measures program execution only. It excludes the NIC driver and memory costs, so it is a per-packet cost, not a throughput figure.

| Configuration | Loaded instructions | Time per packet |
| --- | --- | --- |
| Default | 115 | 16.5 ns |
| `-debug` | 131 | 469 ns |

Median of 5 runs. Intel Xeon @ 2.10GHz (virtualized, 4 vCPU), Linux 6.18, clang 18, Go 1.24.

Reproduce (requires root):
```bash
sudo env "PATH=$PATH" make bench
```

## Development
| Command | Description |
| --- | --- |
| `make` | Generate the eBPF bindings and build `xdp-lb`. |
| `make test` | Run the unit tests. |
| `make bench` | Run the data plane benchmark (requires root). |
| `make clean` | Remove the binary and generated files. |

The eBPF C code is compiled with `-Wall -Werror`.

```
bpf/              eBPF data plane (C)
cmd/              daemon entry point
pkg/config/       configuration loading and validation
pkg/ebpf/         program loading, map programming, benchmark
pkg/telemetry/    counter reporting
```

## Future Roadmap
* **Packet Mutation (XDP_TX):** Implement MAC address rewriting and IPIP encapsulation to achieve Direct Server Return (DSR), allowing the LB to forward packets out to physical hardware.
* **Active Health Checks:** Add a background worker in the Go control plane to ping backend servers and dynamically prune the Consistent Hashing Ring if a node dies.
* **LRU Connection Cache:** Implement a Least Recently Used (LRU) eBPF Map to handle IP fragmentation and graceful backend draining.

## Contributing
1. Open an issue describing the change.
2. Create a branch named `t-<issue-number>-<short-description>`.
3. Run `gofmt`, `go vet ./...` and `make test` before pushing.
4. Open a pull request that references the issue.

## Author
**Mohd Rashid** - [@mohdrashid9678](https://github.com/mohdrashid9678)

## License
[Apache-2.0](LICENSE)
