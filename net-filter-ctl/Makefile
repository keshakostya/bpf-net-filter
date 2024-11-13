CC=gcc
CFLAGS=-g -Wall -Werror -lbpf -lxdp
BUILD_DIR=build

all: per_build net_filter_ctl

per_build:
	mkdir -p build

net_filter_ctl: net_filter_ctl_start net_filter_ctl_stop net_filter_ctl_common
	$(CC) $(CFLAGS) -c net_filter_ctl.c -o $(BUILD_DIR)/net_filter_ctl.o
	$(CC) -o $(BUILD_DIR)/net_filter_ctl $(BUILD_DIR)/*.o

net_filter_ctl_common:
	$(CC) $(CFLAGS) -c net_filter_ctl_common.c -o $(BUILD_DIR)/net_filter_ctl_common.o

net_filter_ctl_stop:
	$(CC) $(CFLAGS) -c net_filter_ctl_stop.c -o $(BUILD_DIR)/net_filter_ctl_stop.o

net_filter_ctl_start:
	$(CC) $(CFLAGS) -c net_filter_ctl_start.c -o $(BUILD_DIR)/net_filter_ctl_start.o