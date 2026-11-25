// bpf/xdp.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "maps.h"
#include "jhash.h"

// Set by the loader before verification. When 0, the verifier removes the
// tracing block from the loaded program.
volatile const __u8 debug_enabled = 0;

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Layer 2: Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // Layer 3: IPv4
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_DROP;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    // Layer 4: TCP
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_DROP;
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end) return XDP_DROP;

    __u32 hash = jhash_5tuple(iph->saddr, iph->daddr, tcph->source, tcph->dest, iph->protocol);

    __u32 ring_index = hash % RING_SIZE;
    __u32 *backend_id = bpf_map_lookup_elem(&ch_ring, &ring_index);
    if (!backend_id) return XDP_PASS;

    __u32 *target_ip = bpf_map_lookup_elem(&backends, backend_id);
    if (!target_ip) return XDP_PASS;

    __u64 *stats = bpf_map_lookup_elem(&backend_stats, backend_id);
    if (stats) {
        __sync_fetch_and_add(stats, 1);
    }

    if (debug_enabled) {
        bpf_printk("TCP Conntrack -> Hash: %u | SRC: %pI4:%d -> Target: %pI4\n",
                   hash, &iph->saddr, bpf_ntohs(tcph->source), target_ip);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
