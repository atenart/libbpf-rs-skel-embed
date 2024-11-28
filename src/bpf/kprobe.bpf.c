#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

const u8 log_level = 0;

SEC("kprobe/placeholder")
int kprobe_placeholder(struct pt_regs *ctx)
{
	return 0;
}

char __license[] SEC("license") = "GPL";
