# I took the libs from the xdp-tutorial repository as i have problems
# compiling with libxdp i built due to kernel version / lib version missmatches
CC=gcc
CFLAGS=-Wall -O2 -I../libs/include -L../libs/lib
LDFLAGS=-l:libxdp.a -l:libbpf.a -lelf -lz
KERN_COMMAND=clang -O2 -g -Wall -target bpf


all: af_xdp_user af_xdp_kern.o

af_xdp_user: af_xdp_user.o common_params.o common_user_bpf_xdp.o
	$(CC) $^ -o $@ $(LDFLAGS)

af_xdp_kern.o: af_xdp_kern.c
	$(KERN_COMMAND) -c $< -o $@

af_xdp_user.o: af_xdp_user.c
	$(CC) $(CFLAGS) -c $< -o $@

common_params.o: common/common_params.c
	$(CC) $(CFLAGS) -c $< -o $@

common_user_bpf_xdp.o: common/common_user_bpf_xdp.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o af_xdp_user