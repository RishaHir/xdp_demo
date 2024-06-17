#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Set this
#define IF_INDEX 12

#define MAX_PACKET_SIZE 1 << 12

// Program zeroes packet and redirects it to another interface.
// If packet was already zeroed then let it pass
SEC("xdp_redirect")
int xdp_redirect_prog(struct xdp_md *xdp)
{
	int action = XDP_PASS;
	// int is_zero = 1;

	// void * data = (void *)(long)xdp->data;
	// void * data_end = (void *)(long)xdp->data_end;

	// // loops have to be used because packet size is not known at compile time
	// for (__u32 i = 0; i < MAX_PACKET_SIZE; i++) {
	// 	// this check is necessary because of verifier
	// 	if (data + i + sizeof(__u8) <= data_end) {
	// 		if (((__u8 *)data)[i] != 0) {
	// 			is_zero = 0;
	// 			break;
	// 		}
	// 	} else {
	// 		break;
	// 	}
	// }

	// if (is_zero) {
	// 	return XDP_PASS;
	// }

	// // builtin_memset() only works with constant size and only up to 1024 bytes
	// for (__u32 i = 0; i < MAX_PACKET_SIZE; i++) {
	// 	// this check is necessary because of verifier
	// 	if (data + i + sizeof(__u8) <= data_end) {
	// 		((__u8 *)data)[i] = 0;
	// 	} else {
	// 		break;
	// 	}
	// }

	// Redirect to IF_INDEX
	unsigned ifindex = IF_INDEX;
	action = bpf_redirect(ifindex, 0);
	return action;
}
