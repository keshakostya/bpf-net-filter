CC=gcc
CFLAGS=-g  -lbpf -lxdp
BUILD_DIR=build

all: pre_build net_filter_ctl

pre_build:
	mkdir -p build

net_filter_ctl: net_filter_ctl_start net_filter_ctl_stop net_filter_ctl_common net_filter_ctl_acl_parser
	$(CC) $(CFLAGS) -c net_filter_ctl.c -o $(BUILD_DIR)/net_filter_ctl.o
	$(CC) -o $(BUILD_DIR)/net_filter_ctl $(BUILD_DIR)/*.o -lxdp -lbpf

net_filter_ctl_common:
	$(CC) $(CFLAGS) -c net_filter_ctl_common.c -o $(BUILD_DIR)/net_filter_ctl_common.o

net_filter_ctl_stop:
	$(CC) $(CFLAGS) -c net_filter_ctl_stop.c -o $(BUILD_DIR)/net_filter_ctl_stop.o

net_filter_ctl_start:
	$(CC) $(CFLAGS) -c net_filter_ctl_start.c -o $(BUILD_DIR)/net_filter_ctl_start.o

net_filter_ctl_acl_parser:
	$(CC) $(CFLAGS) -c net_filter_ctl_acl_parser.c -o $(BUILD_DIR)/net_filter_ctl_acl_parser.o

clean:
	rm -rf $(BUILD_DIR)