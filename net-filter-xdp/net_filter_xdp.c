#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include "net_filter_xdp.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct net_filter_ace);
    __uint(max_entries, 16);
} acl_map SEC(".maps");

int parse_packet(struct hdr_cursor *hdr,
                 struct net_packet *pkt)
{
  int ret = PKT_PARSE_SUCCESS;

  ret = parse_ethhdr(hdr, &pkt->eth);
  if (ret < 0)
    return ret;

  ret = parse_iphdr(hdr, &pkt->ipv4);
  if (ret < 0)
    return ret;

  pkt->l4hdr.protocol = pkt->ipv4->protocol;
  switch (pkt->l4hdr.protocol)
  {
  case IPPROTO_TCP:
    ret = parse_tcphdr(hdr, &pkt->l4hdr.tcp);
    break;
  case IPPROTO_UDP:
    ret = parse_udphdr(hdr, &pkt->l4hdr.udp);
    break;
  case IPPROTO_ICMP:
    ret = parse_icmphdr(hdr, &pkt->l4hdr.icmp);
    break;
  default:
    break;
  }

  return ret;
}

int redirect_packet(struct xdp_md *ctx, struct net_packet *pkt)
{
  struct bpf_fib_lookup fib_params = {};
  int rc;

  fib_params.family = AF_INET;
	fib_params.tos = pkt->ipv4->tos;
	fib_params.l4_protocol = pkt->ipv4->protocol;
	fib_params.sport = 0;
	fib_params.dport = 0;
	fib_params.tot_len = bpf_ntohs(pkt->ipv4->tot_len);
	fib_params.ipv4_src = pkt->ipv4->saddr;
	fib_params.ipv4_dst = pkt->ipv4->daddr;

  rc = bpf_fib_lookup(ctx, &fib_params, sizeof(struct bpf_fib_lookup), 0);

  switch (rc)
	{
	case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
		if (pkt->eth->h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(pkt->ipv4);

		memcpy(pkt->eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(pkt->eth->h_source, fib_params.smac, ETH_ALEN);
		return bpf_redirect(fib_params.ifindex, 0);
	case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:	   /* dest not allowed; can be dropped */
		return XDP_DROP;
	case BPF_FIB_LKUP_RET_NOT_FWDED:	/* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:	/* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:		/* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:	/* fragmentation required to fwd */
		/* PASS */
		break;
	}

  return XDP_PASS;
}

int get_packet_desicion(struct net_packet *pkt)
{
  struct net_filter_ace *ace = NULL;
  int i = 0;
  int found = 0;

#pragma unroll
  for (i = 0; i < 16; ++i)
  {
    ace = bpf_map_lookup_elem(&acl_map, &i);
    if (!ace)
      continue;

    if (ace->sip.s_addr == pkt->ipv4->addrs.saddr & ace->sip_mask.s_addr)
    {
      found = 1;
    }

    if (found)
    {
      return ace->action == NET_FILTER_ACTION_PERMIT ? XDP_PASS : XDP_DROP;
    }
  }

  return XDP_DROP;
}

SEC("net_filter_xdp")
int net_filter_xdp_prog(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct net_packet pkt = {};
  struct hdr_cursor hdr = {.pos = data, .end = data_end};
  int ret;
  int action;

  ret = parse_packet(&hdr, &pkt);
  if (ret < 0)
  {
    bpf_printk("Parse packet error (%d)\n", ret);
    return XDP_PASS;
  }

  action = get_packet_desicion(&pkt);
  if (action == XDP_DROP)
    return XDP_DROP;

  return redirect_packet(ctx, &pkt);
}

char _license[] SEC("license") = "GPL";
