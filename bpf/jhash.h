#ifndef __JHASH_H
#define __JHASH_H

#include <linux/types.h>

// Hash based on five tuples
static __always_inline __u32 jhash_5tuple(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto) {
    __u32 hash = 0;
    hash += saddr; hash += (hash << 10); hash ^= (hash >> 6);
    hash += daddr; hash += (hash << 10); hash ^= (hash >> 6);
    hash += sport; hash += (hash << 10); hash ^= (hash >> 6);
    hash += dport; hash += (hash << 10); hash ^= (hash >> 6);
    hash += proto; hash += (hash << 10); hash ^= (hash >> 6);
    hash += (hash << 3); hash ^= (hash >> 11); hash += (hash << 15);
    return hash;
}

#endif