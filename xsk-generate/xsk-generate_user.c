/* SPDX-License-Identifier: GPL-2.0 */
// This work is based on:
// https://github.com/xdp-project/xdp-tutorial/tree/master/advanced03-AF_XDP
// The files were modified 14.6.2024 by Richard Hyroš
// As per GPL-2.0 licence there is no warranty of any kind

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_stats.h"

#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h> 
#include <net/ethernet.h>

static struct xdp_program *prog;
int xsk_map_fd;

struct config cfg = {
	.ifindex   = -1,
	.do_tx_demo = false,
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{{"help",			no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",			required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",		no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode",	no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",		no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",			no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",			no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",		no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",			required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",		no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"quiet",			no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",		required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",		required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{"tx-demo",		no_argument,		NULL, 't' },
	 "Transmits packets with all bytes changed to 'A'"},

	{{"print-stats",	no_argument,		NULL, 's' },
	 "prints stats"},
	
	{{0, 0, NULL,  0 }, NULL, false}
};


static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
				   NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

// static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
// {
// 	return xsk->umem_frame_free;
// }

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
							struct xsk_umem_info *umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	int i;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	xsk_cfg.bind_flags |= XDP_USE_NEED_WAKEUP;
	xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);
	if (ret)
		goto error_exit;

	/* Initialize umem frame allocation */
	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}


static inline unsigned free_tx_buffs(struct xsk_socket_info *xsk) {
	unsigned idx_tx = 0;
	unsigned ready = xsk_ring_cons__peek(&xsk->umem->cq, 64, &idx_tx);
	for (unsigned i = 0; i < ready; i++) {
		xsk_free_umem_frame(xsk, *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_tx++));
	}
	xsk_ring_cons__release(&xsk->umem->cq, ready);
	return ready;
}

#define PKT_LEN 256
static inline int tx_burst(struct xsk_socket_info *xsk, unsigned nb)
{
	unsigned idx_tx, burst = 0;
	unsigned burst_size = nb;
	unsigned len = PKT_LEN;
	unsigned i;
	int ret = 0;

	// collect done buffers
	while((ret = free_tx_buffs(xsk)));

	burst = xsk_ring_prod__reserve(&xsk->tx, burst_size, &idx_tx);

	for (i = 0; i < burst; i++) {
		uint64_t addr = xsk_alloc_umem_frame(xsk);
		struct xdp_desc *desc = xsk_ring_prod__tx_desc(&xsk->tx, idx_tx++);
		desc->addr = addr;
		desc->len = len;
		void *data = xsk_umem__get_data(xsk->umem->buffer, desc->addr);
		memset(data, 'X', len);
		xsk->stats.tx_bytes += len;
	}
	xsk_ring_prod__submit(&xsk->tx, i);
	xsk->stats.tx_packets += i;
	/* Do we need to wake up the kernel for transmission */
	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	return ret;
}

// Generic xdp can only take 32 buffs
#define BURST_SIZE 32
static void tx_loop(struct config *cfg,
			   struct xsk_socket_info *xsk_socket)
{
	struct pollfd fds[2];
	int ret, nfds = 1;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
	fds[0].events = POLLIN;

	while(!global_exit) {
		if (cfg->xsk_poll_mode) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}
		if(tx_burst(xsk_socket, BURST_SIZE) < 0){
			fprintf(stderr, "Error sending packets. Maybe generic XSK can deal with bursts of 32 packets max?\n");
			break;
		}
	}
}


static void exit_application(int signal)
{
	int err;

	cfg.unload_all = true;
	err = do_unload(&cfg);
	if (err) {
		fprintf(stderr, "Couldn't detach XDP program on iface '%s' : (%d)\n",
			cfg.ifname, err);
	}

	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	int ret;
	void *packet_buffer;
	uint64_t packet_buffer_size;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	pthread_t stats_poll_thread;
	int err;
	char errmsg[1024];

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	// if no program load xsk-generate_kern.o
	if (cfg.filename[0] == 0) {
		snprintf(cfg.filename, 512, "xsk-generate_kern.o");
	}

	// struct bpf_map *map;

	xdp_opts.open_filename = cfg.filename;
	xdp_opts.prog_name = cfg.progname;
	xdp_opts.opts = &opts;

	if (cfg.progname[0] != 0) {
		xdp_opts.open_filename = cfg.filename;
		xdp_opts.prog_name = cfg.progname;
		xdp_opts.opts = &opts;

		prog = xdp_program__create(&xdp_opts);
	} else {
		prog = xdp_program__open_file(cfg.filename,
						NULL, &opts);
	}
	err = libxdp_get_error(prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program: %s\n", errmsg);
		return err;
	}

	err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);

	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
			cfg.ifname, errmsg, err);
		return err;
	}

	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Start thread to do statistics display */
	if (cfg.print_stats) {
		ret = pthread_create(&stats_poll_thread, NULL, stats_poll,
				     xsk_socket);
		if (ret) {
			fprintf(stderr, "ERROR: Failed creating statistics thread "
				"\"%s\"\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* send packets asap */
	tx_loop(&cfg, xsk_socket);

	/* Cleanup */
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);
	return EXIT_OK;
}
