#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <linux/limits.h>
#include "net_filter_ctl.h"

static char map_name_buffer[PATH_MAX];
char *net_filter_construct_map_name(const char *base_dir,
                                    const char *ifname,
                                    const char *map_name)
{
  snprintf(map_name_buffer, PATH_MAX, "%s/%s/%s", base_dir, ifname, map_name);
  return &(map_name_buffer[0]);
}

int net_filter_open_map(const char *map_pin_path,
                        struct bpf_map_info *map_info)
{
  int ret, fd;
  u_int32_t info_len = sizeof(struct bpf_map_info);

  fd = bpf_obj_get(map_pin_path);
  if (fd < 0)
  {
    printf("fail to open bpf map\n");
    return -1;
  }

  if (map_info)
  {
    ret = bpf_obj_get_info_by_fd(fd, map_info, &info_len);
    if (ret)
    {
      fprintf(stderr, "ERR: %s() can't get info \n",
              __func__);
      return -1;
    }
  }

  return fd;
}
