#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <getopt.h>
#include <unistd.h>
#include "net_filter_ctl.h"

void show_usage(char *exe_name)
{
  printf("Usage: %s [OPTION]...\n\n", exe_name);
  printf("      --start         Start packet filtering on interface\n");
  printf("      --stop          Stop packet filtering on interface\n");
  printf("  -i, --interface     Interface name (e.g. eth0)\n");
  printf("  -r, --rules-list    Filename with filtering rules\n");
  printf("  -h, --help          Print this message\n");
}

int parse_arguments(int argc, char **argv, struct net_filter_options *opts)
{
  char ch;
  int option_index;

  struct option long_options[] = 
  {
    {"start",       no_argument, (int *)&opts->prog_mode, NET_FILTER_MODE_START},
    {"stop",        no_argument, (int *)&opts->prog_mode, NET_FILTER_MODE_STOP},
    {"interface",   required_argument, NULL, 'i'},
    {"acl-file",    required_argument, NULL, 'r'},
    {"help",        no_argument, NULL, 'h'},
  };

  if (argc < 2)
  {
    show_usage(argv[0]);
    return -1;
  }

  while ((ch = getopt_long(argc, argv, "i:a:h", long_options, &option_index)) != -1)
  {
    switch (ch)
    {
      case 0:
        if (long_options[option_index].flag != 0)
          break;
        break;
      case 'i':
        strncpy(opts->ifname, optarg, IF_NAMESIZE);
        break;
      case 'a':   
        strncpy(opts->acl_fname, optarg, 4096);
        break;
      case 'h':
        show_usage(argv[0]);
        return 0;
      default:
        show_usage(argv[0]);
        return -1;
    }
  }

  if (opts->prog_mode != NET_FILTER_MODE_START 
      && opts->prog_mode != NET_FILTER_MODE_STOP)
  {
    printf("Error: use start or stop flag\n");
    return -1;
  }

  return 0;
}

int fill_acl_map(struct net_filter_options *opts,
                 struct net_filter_ace acl[], int acl_count)
{
  int i = 0, map_fd, ret = 0;
  char *acl_map = NULL;

  acl_map = net_filter_construct_map_name(NET_FILTER_BASE_MAP_DIR, opts->ifname, 
                                          NET_FILTER_ACL_MAP_NAME);
  map_fd = net_filter_open_map(acl_map, NULL);
  if (map_fd < 0)
  {
    printf("Fail to open map\n");
    return -1;
  }

  for (i = 0; i < acl_count; ++i)
  {
    ret = bpf_map_update_elem(map_fd, &i, &acl[i], 0);
    if (ret)
    {
      goto out;
    }
  }

out:
  close(map_fd);
  return ret;
}

int fill_dev_map(struct net_filter_options *opts)
{
  int i = 0, map_fd, ret = 0;
  char *net_map = NULL;
  int net_ids[] = {3, 4};

  net_map = net_filter_construct_map_name(NET_FILTER_BASE_MAP_DIR, opts->ifname, "tx_port_map");
  map_fd = net_filter_open_map(net_map, NULL);
  if (map_fd < 0)
  {
    printf("Failed to open map\n");
    return -1;
  }

  for (i = 0; i < 2; ++i)
  {
    ret = bpf_map_update_elem(map_fd, &i, &net_ids[i], 0);
    if (ret < 0)
      goto out;
  }

out:
  close(map_fd);
  return ret;
}

int main(int argc, char **argv)
{
  struct net_filter_ace acl[16] = {0};
  struct net_filter_options opts;
  int acl_count = 0;
  int ret;

  if (parse_arguments(argc, argv, &opts))
  {
    printf("fail to parse args\n");
    return 1;
  }

  if (opts.prog_mode == NET_FILTER_MODE_STOP)
  {
    net_filter_ctl_stop(&opts);
    return 0;
  }

  ret = net_filter_parse_acl_file(&opts, acl, &acl_count);
  if (ret)
  {
    printf("Fail to parse acl file\n");
    return 1;
  }

  ret = net_filter_ctl_start(&opts);
  if (ret)
  {
    printf("Fail to start xdp prog\n");
    return 1;
  }

  ret = fill_acl_map(&opts, acl, acl_count);
  if (ret)
  {
    printf("Fail to fill map with rules\n");
    return 1;
  }

  // ret = fill_dev_map(&opts);
  // if (ret)
  // {
  //   printf("Fail to fill map with net ids\n");
  //   return 1;
  // }
  return 0;
}
