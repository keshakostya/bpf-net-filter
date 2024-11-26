#include "net_filter_xdp.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <stdbool.h>

#define ACTION_DEFAULT XDP_PASS

enum net_filter_action
{
  NET_FILTER_ACTION_NONE = 0,
  NET_FILTER_ACTION_PERMIT,
  NET_FILTER_ACTION_DENY,
  NET_FILTER_ACTION_END,
};

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct net_filter_ace);
  __uint(max_entries, ACL_SIZE);
} acl_map SEC(".maps");


static __always_inline int
parse_packet(struct pkt_cursor* crs, struct pkt_info* pkt_info)
{
  int ret;

  ret = parse_ethhdr(crs);
  if (ret < 0)
    return ret;

  ret = parse_iphdr(crs, pkt_info);
  if (ret < 0)
    return ret;

  switch (pkt_info->protocol) {
    case IPPROTO_TCP:
      return parse_tcphdr(crs, pkt_info);
    case IPPROTO_UDP:
      return parse_udphdr(crs, pkt_info);
    case IPPROTO_ICMP:
      return parse_icmphdr(crs, pkt_info);
    default:
      return PARSE_PKT_ERR_UNSUPPORTED;
  }

  return PARSE_PKT_ERR_UNSUPPORTED;
}

static __always_inline int
get_packet_action(struct pkt_info *pkt_info)
{
  struct net_filter_ace *ace = NULL;
  bool pkt_verdict;
  __u32 idx;
  __u32 i;


#pragma unroll(ACL_SIZE)
  for (i = 0; i < ACL_SIZE; ++i)
  {
    idx = i;
    ace = bpf_map_lookup_elem(&acl_map, &idx);
    if (!ace)
      continue;

    pkt_verdict = get_packet_verdict(pkt_info, ace);
    if (!pkt_verdict)
      continue;

    return ace->action == NET_FILTER_ACTION_PERMIT ? XDP_PASS : XDP_DROP;
  }

  return XDP_DROP;
}

int
redirect_packet(struct xdp_md* ctx, struct pkt_info* pkt_info)
{
  struct bpf_fib_lookup fib_params = {};
  int rc;

  fib_params.family = AF_INET;
  fib_params.l4_protocol = pkt_info->protocol;
  fib_params.sport = 0;
  fib_params.dport = 0;
  fib_params.ipv4_src = pkt_info->saddr;
  fib_params.ipv4_dst = pkt_info->daddr;

  rc = bpf_fib_lookup(ctx, &fib_params, sizeof(struct bpf_fib_lookup), 0);

  switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
      // if (pkt_info->eth->h_proto == bpf_htons(ETH_P_IP))
      //   ip_decrease_ttl(pkt_info->ipv4);

      // memcpy(pkt_info->eth->h_dest, fib_params.dmac, ETH_ALEN);
      // memcpy(pkt_info->eth->h_source, fib_params.smac, ETH_ALEN);
      // bpf_printk("redirect pkt_info to %d\n", bpf_ntohs(pkt_info->ipv4->daddr));
      return bpf_redirect(fib_params.ifindex, 0);
    case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:    /* dest not allowed; can be dropped */
      return XDP_DROP;
    case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
      /* PASS */
      break;
  }

  return XDP_PASS;
}

SEC("net_filter_xdp")
int
net_filter_xdp_prog(struct xdp_md* ctx)
{
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;
  struct pkt_cursor crs = { .pos = data, .end = data_end };
  struct pkt_info pkt_info = {};
  int ret;

  ret = parse_packet(&crs, &pkt_info);
  if (ret == PARSE_PKT_ERR_HDR_BAD)
    return XDP_DROP;

  if (ret == PARSE_PKT_ERR_UNSUPPORTED)
    return ACTION_DEFAULT;

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
