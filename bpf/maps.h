#ifndef __MAPS_H
#define __MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define RING_SIZE 251 
#define MAX_BACKENDS 10

// Consistent Hashing Ring Map (Hash -> Backend ID)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RING_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} ch_ring SEC(".maps");

// Backend IP Map (Backend ID -> IP Address)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u32);
} backends SEC(".maps");

// Telemetry Map (Backend ID -> Packet Count)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u64);
} backend_stats SEC(".maps");

#endif