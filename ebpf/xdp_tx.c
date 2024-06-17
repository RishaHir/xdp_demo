#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_tx")
int xdp_tx_prog(struct xdp_md *ctx)
{
    return XDP_TX;
}
