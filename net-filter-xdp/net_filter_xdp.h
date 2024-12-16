#ifndef __XDP_KERN_H__
#define __XDP_KERN_H__

#include <bpf/bpf_endian.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define CHECK_FLAG(v, f) ((v) & (f))

#define ACL_SIZE 16
struct net_filter_ace {

#define NET_FILTER_ACE_SIP (1 << 0)
#define NET_FILTER_ACE_SIP_MASK (1 << 1)
#define NET_FILTER_ACE_DIP (1 << 2)
#define NET_FILTER_ACE_DIP_MASK (1 << 3)
#define NET_FILTER_ACE_PROTOCOL (1 << 4)
#define NET_FILTER_ACE_SPORT (1 << 5)
#define NET_FILTER_ACE_DPORT (1 << 6)
#define NET_FILTER_ACE_ICMP_TYPE (1 << 7)
#define NET_FILTER_ACE_ICMP_CODE (1 << 8)
  u_int32_t flags;

  unsigned int sip;
  unsigned int sip_mask;
  unsigned int dip;
  unsigned int dip_mask;

  u_int8_t protocol;
  u_int16_t sport;
  u_int16_t dport;

  u_int8_t icmp_type;
  u_int8_t icmp_code;

  u_int8_t action;
};

struct pkt_cursor
{
  void* pos;
  void* end;
};

struct pkt_info
{
  unsigned int saddr;
  unsigned int daddr;

  unsigned char protocol;
  unsigned short source;
  unsigned short dest;

  unsigned char icmp_type;
  unsigned char icmp_code;
};

#define PARSE_PKT_ERR_OK 0
#define PARSE_PKT_ERR_UNSUPPORTED -1
#define PARSE_PKT_ERR_HDR_BAD -2

/* Parse ethernet header and retern ethertype */
static __always_inline int
parse_ethhdr(struct pkt_cursor* crs)
{
  struct ethhdr* eth_p = crs->pos;

  if (crs->pos + sizeof(struct ethhdr) > crs->end)
    return PARSE_PKT_ERR_HDR_BAD;

  if (eth_p->h_proto != bpf_htons(ETH_P_IP))
    return PARSE_PKT_ERR_UNSUPPORTED;

  crs->pos += sizeof(struct ethhdr);
  return PARSE_PKT_ERR_OK;
}

static __always_inline int
parse_iphdr(struct pkt_cursor* crs, struct pkt_info* pkt_info)
{
  struct iphdr* ip_p = crs->pos;
  int hdrsize;

  if (crs->pos + sizeof(struct iphdr) > crs->end)
    return PARSE_PKT_ERR_HDR_BAD;

  hdrsize = ip_p->ihl * 4;
  if (crs->pos + hdrsize > crs->end)
    return PARSE_PKT_ERR_HDR_BAD;

  pkt_info->protocol = ip_p->protocol;
  pkt_info->saddr = ip_p->saddr;
  pkt_info->daddr = ip_p->daddr;

  crs->pos += sizeof(struct iphdr);
  return PARSE_PKT_ERR_OK;
}

static __always_inline int
parse_tcphdr(struct pkt_cursor* crs, struct pkt_info* pkt_info)
{
  struct tcphdr* tcp_p = crs->pos;
  int hdrsize;

  if (crs->pos + sizeof(struct tcphdr) > crs->end)
    return PARSE_PKT_ERR_HDR_BAD;

  hdrsize = tcp_p->doff * 4;
  if (crs->pos + hdrsize > crs->end)
    return PARSE_PKT_ERR_HDR_BAD;

  pkt_info->source = tcp_p->source;
  pkt_info->dest = tcp_p->dest;

  crs->pos += sizeof(struct tcphdr);
  return PARSE_PKT_ERR_OK;
}

static __always_inline int
parse_udphdr(struct pkt_cursor* crs, struct pkt_info* pkt_info)
{
  struct udphdr* udp_p = crs->pos;
  int hdrsize;

  if (crs->pos + sizeof(struct udphdr) > crs->end)
    return PARSE_PKT_ERR_HDR_BAD;

  hdrsize = bpf_ntohs(udp_p->len) - sizeof(struct udphdr);
  if (hdrsize < 0)
    return PARSE_PKT_ERR_HDR_BAD;

  pkt_info->source = udp_p->source;
  pkt_info->dest = udp_p->dest;

  crs->pos += sizeof(struct udphdr);
  return PARSE_PKT_ERR_OK;
}

static __always_inline int
parse_icmphdr(struct pkt_cursor* crs, struct pkt_info *pkt_info)
{
  struct icmphdr* icmp_p = crs->pos;

  if (crs->pos + sizeof(struct icmphdr) > crs->end)
    return PARSE_PKT_ERR_HDR_BAD;

  pkt_info->icmp_code = icmp_p->code;
  pkt_info->icmp_type = icmp_p->type;

  crs->pos += sizeof(struct icmphdr);
  return PARSE_PKT_ERR_OK;
}

#define IPV4_COMPARE_BY_MASK(addr1, addr2, mask) ((addr1) == ((addr2) & (mask)))

static __always_inline int
get_packet_verdict(struct pkt_info *pkt_info, struct net_filter_ace *ace)
{
  if (!pkt_info || !ace)
    return 0;

  if (ace->flags == 0)
    return 0;

  if (CHECK_FLAG(ace->flags, NET_FILTER_ACE_SIP))
  {
    if (!IPV4_COMPARE_BY_MASK(ace->sip, pkt_info->saddr, ace->sip_mask))
      return 0;
  }

  if (CHECK_FLAG(ace->flags, NET_FILTER_ACE_DIP))
  {
    if (!IPV4_COMPARE_BY_MASK(ace->dip, pkt_info->daddr, ace->dip_mask))
      return 0;
  }

  if (CHECK_FLAG(ace->flags, NET_FILTER_ACE_PROTOCOL))
  {
    if (ace->protocol != pkt_info->protocol)
      return 0;
  }

  if (CHECK_FLAG(ace->flags, NET_FILTER_ACE_SPORT))
  {
    if (bpf_htons(ace->sport) != pkt_info->source)
      return 0;
  }
  
  if (CHECK_FLAG(ace->flags, NET_FILTER_ACE_DPORT))
  {
    if (bpf_htons(ace->dport) != pkt_info->dest)
      return 0;
  }

  return 1;
}

#endif /* __XDP_KERN_H__ */