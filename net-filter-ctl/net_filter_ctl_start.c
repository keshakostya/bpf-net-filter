#include <stdio.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include "net_filter_ctl.h"

int net_filter_ctl_start(struct net_filter_options *opts)
{
  int ret, ifindex, map_fd;
  struct xdp_program *prog;
  struct bpf_object *bpf_obj;
  char map_dir[PATH_MAX];

  ifindex = if_nametoindex(opts->ifname);
  if (ifindex == 0)
    return -1;

  prog = xdp_program__open_file(NET_FILTER_PROGRAM_FILE, 
                                NET_FILTER_PROGRAM_SECTION, NULL);
  if (!prog)
  {
    return -1;
  }

  ret = xdp_program__attach(prog, ifindex, XDP_MODE_NATIVE, 0);
  if (ret)
  {
    xdp_program__close(prog);
    return ret;
  }

  // char *map_name = net_filter_construct_map_name(NET_FILTER_BASE_MAP_DIR, opts->ifname, "acl_map");

  snprintf(map_dir, PATH_MAX, "%s/%s", NET_FILTER_BASE_MAP_DIR, opts->ifname);
  bpf_obj = xdp_program__bpf_obj(prog);
  ret = bpf_object__pin_maps(bpf_obj, map_dir);
	if (ret)
		return -1;

  return 0;
}
