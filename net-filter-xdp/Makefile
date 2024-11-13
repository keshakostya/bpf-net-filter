CC=clang
CFLAGS=-O2 -g -Wall -target bpf
BUILD_DIR=build

all: per_build net_filter_xdp

per_build:
	mkdir -p build

net_filter_xdp:
	$(CC) $(CFLAGS) -c net_filter_xdp.c -o $(BUILD_DIR)/net_filter_xdp.o