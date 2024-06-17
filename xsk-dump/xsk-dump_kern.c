/* SPDX-License-Identifier: GPL-2.0 */
// This work is based on:
// https://github.com/xdp-project/xdp-tutorial/tree/master/advanced03-AF_XDP
// The files were modified 14.6.2024 by Richard Hyroš
// As per GPL-2.0 licence there is no warranty of any kind

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp_prog")
int xdp_dump_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;

    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map, &index)) {
        return bpf_redirect_map(&xsks_map, index, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
