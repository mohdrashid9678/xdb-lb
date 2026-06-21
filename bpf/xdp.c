// bpf/xdp_prog.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet Header 
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP; // Drop malformed packets that cut short
    }

    // Isolate non-IPv4 traffic immediately
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IPv4 Header 
    // Position the IP header pointer right after the Ethernet header
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) {
        return XDP_DROP;
    }

    // We only want to balance TCP traffic for our initial implementation
    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Parse TCP Header 
    // IP headers can have variable options. The field 'ihl' (Internet Header Length)
    // tells us exactly how many 32-bit words long the IP header is.
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_DROP; // Invalid IP header length
    }

    // Position the TCP header pointer dynamically using the variable length
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end) {
        return XDP_DROP;
    }

    // Extract Network Tuple 
    __u32 src_ip = __constant_ntohl(iph->saddr);
    __u32 dst_ip = __constant_ntohl(iph->daddr);
    __u16 src_port = __constant_ntohs(tcph->source);
    __u16 dst_port = __constant_ntohs(tcph->dest);

    bpf_printk("TCP Conntrack -> SRC: %pI4:%d | DST: %pI4:%d\n", &iph->saddr, src_port, &iph->daddr, dst_port);

    // Eventually, this is where we modify packet targets. For now, we still let it pass.
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";