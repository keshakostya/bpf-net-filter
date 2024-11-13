#ifndef __NET_FILTER_H__
#define __NET_FILTER_H__

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#undef AF_INET
#define AF_INET 2

enum error_e {
  PKT_PARSE_SUCCESS     = 0,
  PKT_PARSE_HDR_UNKNOWN = -1000,
  PKT_PARSE_HDR_BAD,
  PKT_PARSE_TTL_END,
  PKT_PARSE_L3_PROTO_UNSUPPORTED,
  PKT_PARSE_L4_PROTO_UNSUPPORTED,
};

struct hdr_cursor
{
  void *pos;
  void *end;
};

struct net_packet
{
  /* l2 info */
  struct ethhdr *eth;

  /* l3 info */
  struct iphdr *ipv4; // TODO: add ipv6 support

  /* l4 info */
  struct l4hdr
  {
    __u8 protocol;
    union
    {
      struct icmphdr *icmp;
      struct tcphdr *tcp;
      struct udphdr *udp;
    };
  } l4hdr;
};

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline int parse_ethhdr(struct hdr_cursor *hdr,
                                        struct ethhdr **eth)
{
  struct ethhdr *eth_p = hdr->pos;

  if (hdr->pos + sizeof(struct ethhdr) > hdr->end)
    return PKT_PARSE_HDR_BAD;

  if (eth_p->h_proto != bpf_htons(ETH_P_IP))
    return PKT_PARSE_L3_PROTO_UNSUPPORTED;

  hdr->pos = eth_p + 1;
  *eth = eth_p;
  return PKT_PARSE_SUCCESS;
}

static __always_inline int parse_iphdr(struct hdr_cursor *hdr,
                                       struct iphdr **ip)
{
  struct iphdr *ip_p = hdr->pos;
  int hdrsize;

  if (hdr->pos + sizeof(struct iphdr) > hdr->end)
    return PKT_PARSE_HDR_BAD;

  hdrsize = ip_p->ihl * 4;
  if (hdr->pos + hdrsize > hdr->end)
    return PKT_PARSE_HDR_BAD;

  if (ip_p->ttl <= 1)
    return PKT_PARSE_TTL_END;

  hdr->pos = ip_p + 1;
  *ip = ip_p;
  return PKT_PARSE_SUCCESS;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *hdr,
                                        struct tcphdr **tcp)
{
  struct tcphdr *tcp_p = hdr->pos;
  int hdrsize;

  if (hdr->pos + sizeof(struct tcphdr) > hdr->end)
    return PKT_PARSE_HDR_BAD;

  hdrsize = tcp_p->doff * 4;
  if (hdr->pos + hdrsize > hdr->end)
    return PKT_PARSE_HDR_BAD;

  hdr->pos = tcp_p + 1;
  *tcp = tcp_p;
  return PKT_PARSE_SUCCESS;
}

static __always_inline int parse_udphdr(struct hdr_cursor *hdr,
                                        struct udphdr **udp)
{
  struct udphdr *udp_p = hdr->pos;
  int len;

  if (hdr->pos + sizeof(struct udphdr) > hdr->end)
    return PKT_PARSE_HDR_BAD;

  len = bpf_ntohs(udp_p->len) - sizeof(struct udphdr);
  if (len < 0)
    return PKT_PARSE_HDR_BAD;

  hdr->pos = udp_p + 1;
  *udp = udp_p;
  return PKT_PARSE_SUCCESS;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *hdr,
                                         struct icmphdr **icmphdr)
{
  struct icmphdr *icmp = hdr->pos;

  if (hdr->pos + sizeof(struct icmphdr) > hdr->end)
    return PKT_PARSE_HDR_BAD;

  hdr->pos = icmp + 1;
  *icmphdr = icmp;
  return PKT_PARSE_SUCCESS;
}

#endif /* __NET_FILTER_H__ */
