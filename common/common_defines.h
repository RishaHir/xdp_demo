// This work is based on:
// https://github.com/xdp-project/xdp-tutorial/tree/master/advanced03-AF_XDP
// The files were modified 14.6.2024 by Richard Hyroš
// There is no warranty of any kind

#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <net/if.h>
#include <linux/types.h>
#include <stdbool.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct config {
	enum xdp_attach_mode attach_mode;
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	char redirect_ifname_buf[IF_NAMESIZE];
	bool do_unload;
	__u32 prog_id;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progname[32];
	char src_mac[18];
	char dest_mac[18];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_poll_mode;
	bool unload_all;
	bool do_tx_demo;
	bool print_stats;
};

struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
};

/* Defined in common_params.o */
extern int verbose;
extern bool global_exit;

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#endif /* __COMMON_DEFINES_H */
