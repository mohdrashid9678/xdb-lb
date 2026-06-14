# XDP-LB: High-Performance Layer 4 Load Balancer

A high-throughput, kernel-level Layer 4 load balancer bypassing the standard Linux networking stack using eBPF and XDP (eXpress Data Path). 

## Architecture
* **Data Plane:** Written in C, running directly inside the NIC driver via XDP. Handles consistent hashing and NAT/DSR routing.
* **Control Plane:** Written in Go (`cilium/ebpf`). Manages backend health checks and dynamically orchestrates kernel BPF maps.

## Author
Mohd Rashid