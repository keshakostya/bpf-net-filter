#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <getopt.h>
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

int main(int argc, char **argv)
{
  struct net_filter_ace acl[16] = {0};
  struct net_filter_options opts;
  int i;


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

  net_filter_parse_acl_file(&opts, acl, &i);
  net_filter_ctl_start(&opts);
  return 0;
}
