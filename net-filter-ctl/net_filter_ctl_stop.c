#include <stdio.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <string.h>
#include <unistd.h>
#include "net_filter_ctl.h"

int net_filter_ctl_stop(struct net_filter_options *opts)
{
  int ifindex = 0;
  struct xdp_multiprog *mp;
  struct xdp_program *prog = NULL;
  int mode = 0;
  int ret;
  struct bpf_object *bpf_obj;
  char map_dir[PATH_MAX];

  ifindex = if_nametoindex(opts->ifname);
  if (!ifindex)
  {
    return -1;
  }

  prog = xdp_program__open_file(NET_FILTER_PROGRAM_FILE, 
                                NET_FILTER_PROGRAM_SECTION, NULL);
  if (!prog)
  {
    return -1;
  }
  
  bpf_obj = xdp_program__bpf_obj(prog);
  snprintf(map_dir, PATH_MAX, "%s/%s", NET_FILTER_BASE_MAP_DIR, opts->ifname);
  ret = bpf_object__unpin_maps(bpf_obj, map_dir);
  if (ret)
  {
    fprintf(stderr, "Fail to unpin maps\n");
    goto out;
  }

  mp = xdp_multiprog__get_from_ifindex(ifindex);
  if (!mp)
  {
    ret = -1;
    goto out;
  }
  else if (libxdp_get_error(mp))
  {
    ret = -1;
    goto out;
  }

  prog = NULL;
  while ((prog = xdp_multiprog__next_prog(prog, mp)))
  {
    if (strcmp(xdp_program__name(prog), NET_FILTER_PROGRAM_NAME) == 0)
    {
      mode = xdp_multiprog__attach_mode(mp);
      goto found;
    }
  }

  if (xdp_multiprog__is_legacy(mp))
  {
    prog = xdp_multiprog__main_prog(mp);
    if (strcmp(xdp_program__name(prog), NET_FILTER_PROGRAM_NAME) == 0)
    {
      mode = xdp_multiprog__attach_mode(mp);
      goto found;
    }
  }

  prog = xdp_multiprog__hw_prog(mp);
	if (strcmp(xdp_program__name(prog), NET_FILTER_PROGRAM_NAME) == 0)
  {
		mode = XDP_MODE_HW;
		goto found;
	}
found:
  printf("detach program %s\n", xdp_program__name(prog));
  xdp_program__detach(prog, ifindex, mode, 0);
out:
  xdp_multiprog__close(mp);
  return ret;
}
