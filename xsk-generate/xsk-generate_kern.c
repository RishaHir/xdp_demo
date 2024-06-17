#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

// dummy xsk prog
SEC("xdp_prog")
int xdp_generate_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}

