#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>

#define INTERFACE "eth0"  // Change to your network interface name
#define BLOCK_PORT 4040

int main() {
    struct bpf_object *obj;
    int prog_fd, map_fd;
    int ifindex = if_nametoindex(INTERFACE);
    if (ifindex == 0) {
        perror("Invalid interface");
        return 1;
    }

    obj = bpf_object__open_file("drop_port_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog_fd = bpf_program_fd(bpf_object_find_program_by_name(obj, "xdp_drop_tcp_port"));
    map_fd = bpf_object__find_map_fd_by_name(obj, "block_port_map");

    __u32 key = 0;
    __u16 port = BLOCK_PORT;
    if (bpf_map_update_elem(map_fd, &key, &port, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        return 1;
    }

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        perror("bpf_set_link_xdp_fd");
        return 1;
    }

    printf("eBPF program loaded. Dropping TCP packets on port %d\n", BLOCK_PORT);
    printf("Press Ctrl+C to exit\n");

    while (1)
        sleep(10);

    return 0;
}
