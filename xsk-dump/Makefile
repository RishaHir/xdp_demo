CC=gcc
CFLAGS=-Wall -O2 -I../libs/include
LDFLAGS=-L../libs/lib -l:libxdp.a -l:libbpf.a -lelf -lz
# LDFLAGS=-lxdp -lbpf -lelf -lz
KERN_COMMAND=clang -O2 -g -Wall -target bpf


all: xsk-dump xsk-dump_kern.o

xsk-dump: xsk-dump_user.o common_params.o common_user_bpf_xdp.o common_stats.o
	$(CC) $^ -o $@ $(LDFLAGS)

xsk-dump_kern.o: xsk-dump_kern.c
	$(KERN_COMMAND) -c $< -o $@

xsk-dump_user.o: xsk-dump_user.c
	$(CC) $(CFLAGS) -c $< -o $@

common_params.o: ../common/common_params.c
	$(CC) $(CFLAGS) -c $< -o $@

common_user_bpf_xdp.o: ../common/common_user_bpf_xdp.c
	$(CC) $(CFLAGS) -c $< -o $@

common_stats.o: ../common/common_stats.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o xsk-dump_user