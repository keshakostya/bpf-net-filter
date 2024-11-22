#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "net_filter_ctl.h"

#define NET_FILTER_PORT_MIN 0
#define NET_FILTER_PORT_MAX (1 << 16 - 1)

#define NET_FILTER_ICMP_TYPE_MIN 0
#define NET_FILTER_ICMP_TYPE_MAX (1 << 8 - 1)

#define NET_FILTER_ICMP_CODE_MIN 0
#define NET_FILTER_ICMP_CODE_MAX (1 << 8 - 1)

#define NET_FILTER_PARSE_INT_RANGE(name, str, val, min_val, max_val) \
  do                                                                 \
  {                                                                  \
    char *endptr = NULL;                                             \
    (val) = strtoul((str), &endptr, 10);                             \
    if (!endptr || *endptr != '\0')                                  \
    {                                                                \
      fprintf(stderr, "Fail to parse %s (%s)\n", (name), (str));                   \
      return 1;                                                      \
    }                                                                \
                                                                     \
    if (!((min_val) <= (val) && (val) <= (max_val)))                 \
    {                                                                \
      fprintf(stderr, "fffFail to parse %s (%d) %d %d\n", (name), (val), (min_val), (max_val));                   \
      return 1;                                                      \
    }                                                                \
  } while (0);

#define NET_FILTER_PARSE_IPV4_ADDR(name, str, val) \
  do                                               \
  {                                                \
    int ret;                                       \
    ret = inet_pton(AF_INET, (str), &(val));       \
    if (ret != 1)                                  \
    {                                              \
      fprintf(stderr, "Fail to parse %s\n", name); \
      return 1;                                    \
    }                                              \
  } while (0)

static char raw_acl_tokens[NET_FILTER_ACL_MAX_SIZE][NET_FILTER_ACE_MAX_FIELDS][NET_FILTER_ACE_MAX_FIELD_LEN];

#define FIELD_NAME_SIZE 20
int net_filter_parse_ace_field(char *field_name, char *field_value, 
                               struct net_filter_ace *ace)
{
  if (strncmp(field_name, "sip", FIELD_NAME_SIZE) == 0)
  {
    NET_FILTER_PARSE_IPV4_ADDR(field_name, field_value, ace->sip);
    ace->flags |= NET_FILTER_ACE_SIP;
  }
  else if (strncmp(field_name, "sip-mask", FIELD_NAME_SIZE) == 0)
  {
    NET_FILTER_PARSE_IPV4_ADDR(field_name, field_value, ace->sip_mask);
    ace->flags |= NET_FILTER_ACE_SIP_MASK;
  }
  else if (strncmp(field_name, "dip", FIELD_NAME_SIZE) == 0)
  {
    NET_FILTER_PARSE_IPV4_ADDR(field_name, field_value, ace->dip);
    ace->flags |= NET_FILTER_ACE_DIP;
  }
  else if (strncmp(field_name, "dip-mask", FIELD_NAME_SIZE) == 0)
  {
    NET_FILTER_PARSE_IPV4_ADDR(field_name, field_value, ace->dip_mask);
    ace->flags |= NET_FILTER_ACE_DIP_MASK;
  }
  else if (strncmp(field_name, "protocol", FIELD_NAME_SIZE) == 0)
  {
    NET_FILTER_PARSE_INT_RANGE(field_name, field_value, 
                               ace->protocol, IPPROTO_IP, IPPROTO_MAX);
    ace->flags |= NET_FILTER_ACE_PROTOCOL;
  }
  else if (strncmp(field_name, "sport", FIELD_NAME_SIZE) == 0)
  {
     NET_FILTER_PARSE_INT_RANGE(field_name, field_value, 
                               ace->sport, NET_FILTER_PORT_MIN, 
                               NET_FILTER_PORT_MAX);
    ace->flags |= NET_FILTER_ACE_SPORT;
  }
  else if (strncmp(field_name, "dport", FIELD_NAME_SIZE) == 0)
  {
     NET_FILTER_PARSE_INT_RANGE(field_name, field_value, 
                               ace->dport, NET_FILTER_PORT_MIN, 
                               NET_FILTER_PORT_MAX);
    ace->flags |= NET_FILTER_ACE_DPORT;
  }
  else if (strncmp(field_name, "icmp-type", FIELD_NAME_SIZE) == 0)
  {
     NET_FILTER_PARSE_INT_RANGE(field_name, field_value, 
                               ace->dport, NET_FILTER_ICMP_TYPE_MIN, 
                               NET_FILTER_ICMP_TYPE_MAX);
    ace->flags |= NET_FILTER_ACE_ICMP_TYPE;
  }
  else if (strncmp(field_name, "icmp-code", FIELD_NAME_SIZE) == 0)
  {
     NET_FILTER_PARSE_INT_RANGE(field_name, field_value, 
                               ace->dport, NET_FILTER_ICMP_CODE_MIN, 
                               NET_FILTER_ICMP_CODE_MAX);
    ace->flags |= NET_FILTER_ACE_ICMP_CODE;
  }
  else if (strncmp(field_name, "action", FIELD_NAME_SIZE) == 0)
  {
    if (strncmp(field_value, "deny", sizeof("deny") - 1) == 0)
      ace->action = NET_FILTER_ACTION_DENY;
    else if (strncmp(field_value, "permit", sizeof("permit") - 1) == 0)
      ace->action = NET_FILTER_ACTION_PERMIT;
    else
    {
      fprintf(stderr, "Unkown action %s\n", field_value);
      return 1;
    }
  }
  else
  {
    fprintf(stderr, "Unknown ace field %s\n", field_name);
    return 1;
  }

  return 0;
}

int net_filter_parse_ace(int ace_num, struct net_filter_ace *ace)
{
  int i = 0;
  int ret = 0;
  char *field_name = NULL, *field_value = NULL;

  for (i = 0; i < NET_FILTER_ACE_MAX_FIELDS; ++i)
  {
    if (*(raw_acl_tokens[ace_num][i]) == '\0')
      break;

    field_name = strtok(raw_acl_tokens[ace_num][i], "=");
    if (!field_name)
      return -1;

    field_value = strtok(NULL, "=");
    if (!field_value)
      return -1;

    ret = net_filter_parse_ace_field(field_name, field_value, ace);
    if (ret != 0)
      return ret;
  }

  return 0;
}

int net_filter_tokenize_acl_file(FILE *fp, int *ace_count)
{
  char line[1025];
  int i = 0, j = 0;
  char *tok1 = NULL;

  while(fgets(line, sizeof(line), fp))
  {
    j = 0;
    line[strcspn(line, "\n\r")] = '\0';
    if (!strlen(line))
      continue;

    tok1 = strtok(line, " ");
    if (!tok1)
      return 1;

    do
    {
      strncpy(raw_acl_tokens[i][j], tok1, NET_FILTER_ACE_MAX_FIELD_LEN);
      j++;
    } while ((tok1 = strtok(NULL, " ")));
    i++;
  }

  if (i == 0)
    return 1;

  *ace_count = i;
  return 0;
}

int net_filter_parse_acl_file(struct net_filter_options *opts,
                              struct net_filter_ace acl[],
                              int *ace_count)
{
  FILE *fp = NULL;
  int ret  = 0;
  int i = 0;

  fp = fopen(opts->acl_fname, "r");
  if (!fp)
    return -1;

  ret = net_filter_tokenize_acl_file(fp, ace_count);
  if (ret)
    goto out;

  for (i = 0; i < *ace_count; ++i)
  {
    ret = net_filter_parse_ace(i, &(acl[i]));
    if (ret != 0)
      goto out;
  }
out:
  if (fp)
    fclose(fp);

  return ret;
}
