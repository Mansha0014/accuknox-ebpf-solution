#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/bpf.h>
#include <fcntl.h>

#define CGROUP_PATH "/sys/fs/cgroup/mygroup"  // Replace with your actual cgroup path

int main() {
    struct bpf_object *obj;
    int prog_fd, cgroup_fd;

    obj = bpf_object__open_file("filter_by_proc_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog_fd = bpf_program_fd(bpf_object_find_program_by_name(obj, "block_ports_except_target"));

    cgroup_fd = open(CGROUP_PATH, O_DIRECTORY | O_RDONLY);
    if (cgroup_fd < 0) {
        perror("Failed to open cgroup");
        return 1;
    }

    if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_INET4_CONNECT, 0) != 0) {
        perror("Failed to attach BPF program");
        return 1;
    }

    printf("eBPF program attached. Only port 4040 allowed for process 'myprocess'.\n");
    return 0;
}
