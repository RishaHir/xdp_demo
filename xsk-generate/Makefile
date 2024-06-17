CC=gcc
CFLAGS=-Wall -O2 -I../libs/include
LDFLAGS=-L../libs/lib -l:libxdp.a -l:libbpf.a -lelf -lz
# LDFLAGS=-lxdp -lbpf -lelf -lz
KERN_COMMAND=clang -O2 -g -Wall -target bpf


all: xsk-generate xsk-generate_kern.o

xsk-generate: xsk-generate_user.o common_params.o common_user_bpf_xdp.o common_stats.o
	$(CC) $^ -o $@ $(LDFLAGS)

xsk-generate_kern.o: xsk-generate_kern.c
	$(KERN_COMMAND) -c $< -o $@

xsk-generate_user.o: xsk-generate_user.c
	$(CC) $(CFLAGS) -c $< -o $@

common_params.o: ../common/common_params.c
	$(CC) $(CFLAGS) -c $< -o $@

common_user_bpf_xdp.o: ../common/common_user_bpf_xdp.c
	$(CC) $(CFLAGS) -c $< -o $@

common_stats.o: ../common/common_stats.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o xsk-generate