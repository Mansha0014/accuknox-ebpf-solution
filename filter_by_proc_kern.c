#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define TARGET_PORT 4040
#define PROC_NAME "myprocess"

SEC("cgroup/connect4")
int block_ports_except_target(struct bpf_sock_addr *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (__builtin_memcmp(comm, PROC_NAME, sizeof(PROC_NAME) - 1) == 0) {
        if (bpf_ntohs(ctx->user_port) != TARGET_PORT) {
            return 0; // Deny
        }
    }

    return 1; // Allow
}

char LICENSE[] SEC("license") = "GPL";
