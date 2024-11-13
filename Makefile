NET_FILTER_XDP_DIR=./net-filter-xdp
NET_FILTER_CTL_DIR=./net-filter-ctl
BUILD_DIR=build
TARGET_DIR=target

all: pre_build net_filter_xdp net_filter_ctl post_build

pre_build:
	mkdir -p target

net_filter_xdp:
	$(MAKE) -C $(NET_FILTER_XDP_DIR)

net_filter_ctl:
	$(MAKE) -C $(NET_FILTER_CTL_DIR)

post_build:
	cp $(NET_FILTER_CTL_DIR)/$(BUILD_DIR)/net_filter_ctl $(TARGET_DIR)
	cp $(NET_FILTER_XDP_DIR)/$(BUILD_DIR)/net_filter_xdp.o $(TARGET_DIR)