// bpf/xdp.c — XDP data plane.
//
// This program runs inside the NIC driver's receive path, once per packet,
// before the kernel allocates an sk_buff. Everything here is on the hot path:
// every instruction, map lookup and helper call is paid per packet, so the
// rule for this file is "do nothing that is not needed to pick a verdict".
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "maps.h"
#include "jhash.h"

// Load-time configuration.
//
// `volatile const` globals are placed in the .rodata section, which the loader
// exposes as a frozen, read-only array map. The Go control plane rewrites the
// value *before* the program is loaded (see pkg/ebpf/ebpf.go). Because the map
// is frozen, the verifier treats the value as a known constant and removes any
// branch that depends on it. With debug_enabled == 0 the tracing block below
// is deleted from the loaded program entirely: it costs zero instructions per
// packet instead of a runtime check plus a helper call.
//
// `volatile` only stops clang from folding the default value at compile time.
volatile const __u8 debug_enabled = 0;

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Every pointer dereference must be preceded by a bounds check against
    // data_end. The verifier rejects the program otherwise; it is what makes
    // it safe to run this code on raw packet memory inside the kernel.

    // Layer 2: Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // Layer 3: IPv4
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_DROP;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    // Layer 4: TCP. The IPv4 header is variable length (ihl counts 32-bit
    // words), so the TCP header offset has to be computed, then re-checked.
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_DROP;
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end) return XDP_DROP;

    // Hash the 5-tuple. Addresses and ports are hashed in network byte order;
    // the hash only needs to be stable per flow, so no byte swap is spent.
    __u32 hash = jhash_5tuple(iph->saddr, iph->daddr, tcph->source, tcph->dest, iph->protocol);

    // Map the hash onto the ring, then the ring slot onto a backend.
    __u32 ring_index = hash % RING_SIZE;
    __u32 *backend_id = bpf_map_lookup_elem(&ch_ring, &ring_index);
    if (!backend_id) return XDP_PASS;

    __u32 *target_ip = bpf_map_lookup_elem(&backends, backend_id);
    if (!target_ip) return XDP_PASS;

    // Telemetry
    __u64 *stats = bpf_map_lookup_elem(&backend_stats, backend_id);
    if (stats) {
        __sync_fetch_and_add(stats, 1);
    }

    // Per-packet tracing. Compiled in, but dead-code-eliminated by the
    // verifier unless the control plane was started with -debug.
    if (debug_enabled) {
        bpf_printk("xdp-lb: hash=%u src=%pI4:%d -> backend=%pI4",
                   hash, &iph->saddr, bpf_ntohs(tcph->source), target_ip);
    }

    // Not forwarded yet: the packet continues to the local stack unchanged.
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
