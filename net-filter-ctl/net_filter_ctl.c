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

int main(int argc, char **argv)
{
  return 0;
}
