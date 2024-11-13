#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "net_filter_ctl.h"

#define FIELD_NAME_SIZE 20
int net_filter_parse_ace_field(char *field_name, char *field_value, 
                               struct net_filter_ace *ace)
{
  unsigned long tmp;
  char *endptr = NULL;

  if (strncmp(field_name, "sip", FIELD_NAME_SIZE) == 0)
  {
    if (inet_pton(AF_INET, field_value, &ace->sip) != 1)
    {
      printf("Invalid sip %s\n", field_value);
      return 1;
    }

    ace->flags |= NET_FILTER_ACE_SIP;
  }
  else if (strncmp(field_name, "dip", FIELD_NAME_SIZE) == 0)
  {
    if (inet_pton(AF_INET, field_value, &ace->dip) != 1)
    {
      printf("Invalid dip %s\n", field_value);
      return 1;
    }

    ace->flags |= NET_FILTER_ACE_DIP;
  }
  else if (strncmp(field_name, "protocol", FIELD_NAME_SIZE) == 0)
  {
    ace->protocol = strtoul(field_value, &endptr, NULL);
    if (!endptr || *endptr != '\0')
    {
      printf("Invalid protocol %s\n", field_value);
      return 1;
    }

    if (ace->protocol >= IPPROTO_MAX)
    {
      printf("Invalid protocol %s\n", field_value);
      return 1;
    }

    ace->flags |= NET_FILTER_ACE_PROTOCOL;
  }
  else if (strncmp(field_name, "protocol", FIELD_NAME_SIZE) == 0)
  {
    ace->protocol = strtoul(field_value, &endptr, NULL);
    if (!endptr || *endptr != '\0')
    {
      printf("Invalid protocol %s\n", field_value);
      return 1;
    }

    if (ace->protocol >= IPPROTO_MAX)
    {
      printf("Invalid protocol %s\n", field_value);
      return 1;
    }

    ace->flags |= NET_FILTER_ACE_PROTOCOL;
  }
}

int net_filter_parse_ace(char *raw_data, struct net_filter_ace *ace)
{
  char *tok;


}

int net_filter_parse_acl_file(struct net_filter_options *opts,
                              struct net_filter_ace acl[])
{
  FILE *fp = NULL;

  fp = fopen(opts->acl_fname, "r");
  if (!fp)
    return -1;
}
