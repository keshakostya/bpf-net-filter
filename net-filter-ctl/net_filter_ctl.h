#ifndef __NET_FILTER_CTL_H__
#define __NET_FILTER_CTL_H__

#include <linux/if.h>
#include <linux/limits.h>
#include <linux/in.h>
#include <xdp/libxdp.h>

#define NET_FILTER_PROGRAM_NAME    "net_filter_xdp.o"
#define NET_FILTER_PROGRAM_SECTION "net_filter_xdp"

enum net_filter_mode
{
  NET_FILTER_MODE_NONE = 0,
  NET_FILTER_MODE_START,
  NET_FILTER_MODE_STOP,
  NET_FILTER_MODE_END,
};

struct net_filter_options
{
  char ifname[IFNAMSIZ];
  char acl_fname[PATH_MAX];
  enum net_filter_mode prog_mode;
};

struct net_filter_md
{
  int ifindex;
  struct xdp_program *prog;
};

#define NET_FILTER_ACL_MAX_SIZE 16

enum net_filter_action
{
  NET_FILTER_ACTION_NONE = 0,
  NET_FILTER_ACTION_PERMIT,
  NET_FILTER_ACTION_DENY,
  NET_FILTER_ACTION_END,
};

#define NET_FILTER_ACE_SIP        (1 << 0)
#define NET_FILTER_ACE_DIP        (1 << 1)
#define NET_FILTER_ACE_PROTOCOL   (1 << 2)
#define NET_FILTER_ACE_SPORT      (1 << 3)
#define NET_FILTER_ACE_DPORT      (1 << 4)
#define NET_FILTER_ACE_ICMP_TYPE  (1 << 5)
#define NET_FILTER_ACE_ICMP_CODE  (1 << 6)
struct net_filter_ace
{
  u_int32_t flags;
  struct in_addr sip;
  struct in_addr dip;

  u_int8_t protocol;
  u_int16_t sport;
  u_int16_t dport;

  u_int8_t icmp_type;
  u_int8_t icmp_code;

  u_int8_t action;
};

int net_filter_ctl_start(struct net_filter_options *opt);
int net_filter_ctl_stop(struct net_filter_options *opt);

#endif /* __NET_FILTER_CTL_H__ */
