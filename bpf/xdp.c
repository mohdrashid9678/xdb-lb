<<<<<<< Updated upstream
#include <linux/bpf.h>
#include <linux/if_ether.h>
=======
// bpf/xdp.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
>>>>>>> Stashed changes
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#include "maps.h"
#include "jhash.h"

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

<<<<<<< Updated upstream
    struct ethhdr *eth = data;

    // Strict verifier bounds check
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }

    // Pass IPv4 traffic, drop or pass others depending on future rules
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        bpf_printk("XDP-LB: IPv4 packet intercepted.\n");
        return XDP_PASS; 
    }

    return XDP_PASS;
=======
    // Layer 2: Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    // Layer 3: IPv4
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) return XDP_DROP;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    // Layer 4: TCP
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_DROP;
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end) return XDP_DROP;

    // Hash calculation
    __u32 hash = jhash_5tuple(iph->saddr, iph->daddr, tcph->source, tcph->dest, iph->protocol);
    
    // Map hash to Consistent Hashing Ring
    __u32 ring_index = hash % RING_SIZE;
    __u32 *backend_id = bpf_map_lookup_elem(&ch_ring, &ring_index);
    if (!backend_id) return XDP_PASS;

    // Lookup target physical IP
    __u32 *target_ip = bpf_map_lookup_elem(&backends, backend_id);
    if (!target_ip) return XDP_PASS;

    // Update Telemetry
    __u64 *stats = bpf_map_lookup_elem(&backend_stats, backend_id);
    if (stats) {
        __sync_fetch_and_add(stats, 1);
    }

    __u32 src_ip = __constant_ntohl(iph->saddr);
    __u16 src_port = __constant_ntohs(tcph->source);
    bpf_printk("TCP Conntrack -> Hash: %u | SRC: %pI4:%d -> Target: %pI4\n", hash, &iph->saddr, src_port, target_ip);

    return XDP_PASS; 
>>>>>>> Stashed changes
}

char __license[] SEC("license") = "Dual MIT/GPL";