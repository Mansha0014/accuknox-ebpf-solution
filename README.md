# Accuknox eBPF Assignment

This repository contains solutions to the eBPF problem statements provided by Accuknox. The solutions demonstrate how to use core Linux kernel primitives like *eBPF, **XDP, and **cgroup hooks* to filter and drop network packets based on port number or process name.

---

## 🔧 Problem 1: Drop TCP Packets on a Specific Port

*Goal:* Drop incoming TCP packets on a specific port (default: 4040) using eBPF XDP.

### Files:
- drop_port_kern.c: eBPF kernel program to drop packets at specified port.
- drop_port_user.c: User-space loader that configures the port and attaches the program to a network interface.

### How to Compile:
```bash
clang -O2 -g -target bpf -c drop_port_kern.c -o drop_port_kern.o
gcc drop_port_user.c -o drop_port_user -lbpf
