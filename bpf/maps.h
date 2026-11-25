#ifndef __MAPS_H
#define __MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// These two sizes are the single source of truth. The Go control plane does
// not repeat them: it reads max_entries back from the compiled object, so the
// two sides cannot drift apart.
#define RING_SIZE 251
#define MAX_BACKENDS 10

// Ring map (ring slot -> backend ID)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RING_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} ch_ring SEC(".maps");

// Backend IP map (backend ID -> IPv4 address, network byte order)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u32);
} backends SEC(".maps");

// Telemetry map (backend ID -> packet count)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u64);
} backend_stats SEC(".maps");

#endif
