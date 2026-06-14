#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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
}

char __license[] SEC("license") = "Dual MIT/GPL";