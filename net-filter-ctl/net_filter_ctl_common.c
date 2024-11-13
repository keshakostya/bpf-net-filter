#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include "net_filter_ctl.h"

int net_filter_common_load_program(struct net_filter_md *nf_md,
                                   struct net_filter_options *opts)
{
  nf_md->ifindex = if_nametoindex(opts->ifname);
  if (nf_md->ifindex < 0)
  {

  }
  return 0;
}
