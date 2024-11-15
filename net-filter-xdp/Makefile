CC=clang
CFLAGS=-O2 -g -Wall -target bpf
BUILD_DIR=build

all: pre_build net_filter_xdp

pre_build:
	mkdir -p build

net_filter_xdp:
	$(CC) $(CFLAGS) -c net_filter_xdp.c -o $(BUILD_DIR)/net_filter_xdp.o

clean:
	rm -rf $(BUILD_DIR)