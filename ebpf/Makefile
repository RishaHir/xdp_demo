COMMAND=clang -g -O2 -Wall --target=bpf 
OBJ=$(patsubst %.c,%.o, $(wildcard *.c))

all: $(OBJ)

%.o: %.c
	$(COMMAND) -c $< -o $@

clean:
	rm *.o