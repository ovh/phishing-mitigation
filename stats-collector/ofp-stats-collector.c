/*
 Copyright (C) 2016, OVH SAS

 This file is part of phishing-mitigation.

 phishing-mitigation is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <sys/time.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <rrd.h>

#define BUFLEN 2048
#define PORT 9997

#define FAIL(...)                                                                                  \
  do                                                                                               \
  {                                                                                                \
    printf(__VA_ARGS__);                                                                           \
    exit(1);                                                                                       \
  } while (0)

void create_rrd_file_if_needed(char *filename)
{
  if (access(filename, F_OK) != 0)
  {
    printf("Creating rrd file\n");

    char *args[] = {
        "", // No idea why we need this, but it works like this...
        filename, "--step", "1",
        // 1
        "DS:ingress_packets:COUNTER:20:0:U",
        // 2
        "DS:ingress_bytes:COUNTER:20:0:U",
        // 3
        "DS:egress_packets:COUNTER:20:0:U",
        // 4
        "DS:egress_bytes:COUNTER:20:0:U",
        // 5
        "DS:drops:COUNTER:20:0:U",
        // 6
        "DS:drops_no_buf:COUNTER:20:0:U",
        // 7
        "DS:drops_ipkt:COUNTER:20:0:U",
        // 8
        "DS:drops_cls_lb:COUNTER:20:0:U",
        // 9
        "DS:icmp_forwarded:ABSOLUTE:20:0:U",
        // 10
        "DS:tcp_forwarded:ABSOLUTE:20:0:U",
        // 11
        "DS:udp_forwarded:ABSOLUTE:20:0:U",
        // 12
        "DS:other_forwarded:ABSOLUTE:20:0:U",

        // 13 no more used
        "DS:unused_1:COUNTER:20:0:U",
        // 14 no more used
        "DS:unused_2:COUNTER:20:0:U",
        // 15 phish_in_packet_matching
        "DS:phish_pkt_match:COUNTER:20:0:U",
        // 16 logger_loop_duration_ms
        "DS:phish_rst_sent:COUNTER:20:0:U",

        // errors 17-87
        "DS:drops_0:ABSOLUTE:20:0:U", "DS:drops_1:ABSOLUTE:20:0:U", "DS:drops_2:ABSOLUTE:20:0:U",
        "DS:drops_3:ABSOLUTE:20:0:U", "DS:drops_4:ABSOLUTE:20:0:U", "DS:drops_5:ABSOLUTE:20:0:U",
        "DS:drops_6:ABSOLUTE:20:0:U", "DS:drops_7:ABSOLUTE:20:0:U", "DS:drops_8:ABSOLUTE:20:0:U",
        "DS:drops_9:ABSOLUTE:20:0:U", "DS:drops_10:ABSOLUTE:20:0:U", "DS:drops_11:ABSOLUTE:20:0:U",
        "DS:drops_12:ABSOLUTE:20:0:U", "DS:drops_13:ABSOLUTE:20:0:U", "DS:drops_14:ABSOLUTE:20:0:U",
        "DS:drops_15:ABSOLUTE:20:0:U", "DS:drops_16:ABSOLUTE:20:0:U", "DS:drops_17:ABSOLUTE:20:0:U",
        "DS:drops_18:ABSOLUTE:20:0:U", "DS:drops_19:ABSOLUTE:20:0:U", "DS:drops_20:ABSOLUTE:20:0:U",
        "DS:drops_21:ABSOLUTE:20:0:U", "DS:drops_22:ABSOLUTE:20:0:U", "DS:drops_23:ABSOLUTE:20:0:U",
        "DS:drops_24:ABSOLUTE:20:0:U", "DS:drops_25:ABSOLUTE:20:0:U", "DS:drops_26:ABSOLUTE:20:0:U",
        "DS:drops_27:ABSOLUTE:20:0:U", "DS:drops_28:ABSOLUTE:20:0:U", "DS:drops_29:ABSOLUTE:20:0:U",
        "DS:drops_30:ABSOLUTE:20:0:U", "DS:drops_31:ABSOLUTE:20:0:U", "DS:drops_32:ABSOLUTE:20:0:U",
        "DS:drops_33:ABSOLUTE:20:0:U", "DS:drops_34:ABSOLUTE:20:0:U", "DS:drops_35:ABSOLUTE:20:0:U",
        "DS:drops_36:ABSOLUTE:20:0:U", "DS:drops_37:ABSOLUTE:20:0:U", "DS:drops_38:ABSOLUTE:20:0:U",
        "DS:drops_39:ABSOLUTE:20:0:U", "DS:drops_40:ABSOLUTE:20:0:U", "DS:drops_41:ABSOLUTE:20:0:U",
        "DS:drops_42:ABSOLUTE:20:0:U", "DS:drops_43:ABSOLUTE:20:0:U", "DS:drops_44:ABSOLUTE:20:0:U",
        "DS:drops_45:ABSOLUTE:20:0:U", "DS:drops_46:ABSOLUTE:20:0:U", "DS:drops_47:ABSOLUTE:20:0:U",
        "DS:drops_48:ABSOLUTE:20:0:U", "DS:drops_49:ABSOLUTE:20:0:U", "DS:drops_50:ABSOLUTE:20:0:U",
        "DS:drops_51:ABSOLUTE:20:0:U", "DS:drops_52:ABSOLUTE:20:0:U", "DS:drops_53:ABSOLUTE:20:0:U",
        "DS:drops_54:ABSOLUTE:20:0:U", "DS:drops_55:ABSOLUTE:20:0:U", "DS:drops_56:ABSOLUTE:20:0:U",
        "DS:drops_57:ABSOLUTE:20:0:U", "DS:drops_58:ABSOLUTE:20:0:U", "DS:drops_59:ABSOLUTE:20:0:U",
        "DS:drops_60:ABSOLUTE:20:0:U", "DS:drops_61:ABSOLUTE:20:0:U", "DS:drops_62:ABSOLUTE:20:0:U",
        "DS:drops_63:ABSOLUTE:20:0:U", "DS:drops_64:ABSOLUTE:20:0:U", "DS:drops_65:ABSOLUTE:20:0:U",
        "DS:drops_66:ABSOLUTE:20:0:U", "DS:drops_67:ABSOLUTE:20:0:U", "DS:drops_68:ABSOLUTE:20:0:U",
        "DS:drops_69:ABSOLUTE:20:0:U", "DS:drops_70:ABSOLUTE:20:0:U",

        // 88
        "DS:bytesBadIp:COUNTER:20:0:U",
        // 89
        "DS:bytesParsed:COUNTER:20:0:U",
        // 90
        "DS:frozen_count:COUNTER:20:0:U",
        // 91
        "DS:max_mp_usage:COUNTER:20:0:U",
        // 92
        "DS:total_host:COUNTER:20:0:U",
        // 93
        "DS:total_url:COUNTER:20:0:U",

        // 94
        "DS:packet_in:COUNTER:20:0:U",
        // 95
        "DS:packet_parsed:COUNTER:20:0:U",
        // 96
        "DS:packet_http_get:COUNTER:20:0:U",
        // 97
        "DS:max_hash_usage:ABSOLUTE:20:0:U",
        // 98
        "DS:cycle_pkt:ABSOLUTE:20:0:U",

        "DS:unused_12:ABSOLUTE:20:0:U", "DS:unused_13:ABSOLUTE:20:0:U",

        "RRA:AVERAGE:0.5:1:172800", // 48h
        "RRA:AVERAGE:0.5:10:25920", // 72h
        "RRA:AVERAGE:0.5:60:10080", // 7j
        "RRA:AVERAGE:0.5:300:8640", // 30j
    };

    const int NB_ARGS = sizeof(args) / sizeof(char *);

    if (rrd_create(NB_ARGS, args) != 0)
      FAIL(rrd_get_error());

    printf("Created \n");

    if (access(filename, F_OK) != 0)
      fprintf(stderr, "Could not create RRD file\n");
    else
    {
      if (chmod(filename, 0644) != 0)
        fprintf(stderr, "Could not chmod RRD file");
    }
  }
}

static char *rrd_dir;
static uint32_t nb_tileras = 0;
static char *tileras[50];
static char *ips[50];
static char *rrds[50];

static void err_usage(char *prog_name)
{
  printf("Usage : %s rrd_dir tilera_name1=ip1 tilera_name2=ip2 ...\n", prog_name);
  exit(1);
}

int main(int argc, char **argv)
{
  if (argc < 3)
    err_usage(argv[0]);

  rrd_dir = argv[1];
  for (int i = 0; i < argc - 2; i++)
  {
    char *tilera = strdup(argv[i + 2]);
    tileras[i] = strtok(tilera, "=");
    if (!tileras[i])
      err_usage(argv[0]);
    ips[i] = strtok(NULL, "=");
    if (!ips[i])
      err_usage(argv[0]);

    rrds[i] = malloc(100);
    sprintf(rrds[i], "%s/%s/%s.rrd", rrd_dir, tileras[i], tileras[i]);

    create_rrd_file_if_needed(rrds[i]);

    printf("%s -- %s -- %s\n", tileras[i], ips[i], rrds[i]);

    nb_tileras++;
  }

  struct sockaddr_in my_addr, cli_addr;
  int sockfd;
  socklen_t slen = sizeof(cli_addr);
  char buf[BUFLEN];

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    FAIL("socket() failed : %s\n", strerror(errno));

  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons(PORT);
  my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1)
    FAIL("bind() failed : %s\n", strerror(errno));

  printf("Listening on port %u...\n", PORT);

  while (1)
  {
    int recv;
    if ((recv = recvfrom(sockfd, buf, BUFLEN, 0, (struct sockaddr *)&cli_addr, &slen)) == -1)
      FAIL("recvfrom() failed : %s\n", strerror(errno));
    char *ip = inet_ntoa(cli_addr.sin_addr);
    printf("Received packet from %s:%d\nData: %s (%d)\n", ip, ntohs(cli_addr.sin_port), buf, recv);

    // Find which tilera it is coming from
    int tilera_i = -1;
    for (int i = 0; i < nb_tileras; i++)
    {
      if (strcmp(ips[i], ip) == 0)
      {
        tilera_i = i;
        break;
      }
    }
    if (tilera_i < 0)
    {
      fprintf(stderr, "Unknown tilera : %s\n", ip);
      continue;
    }

    char *args[50];
    args[0] = "";
    args[1] = rrds[tilera_i];
    char c = buf[0];
    int i = 0;
    int paramCount = 0;
    while (c != '\0')
    {
      if (c == ';')
      {
        buf[i] = ':';
        paramCount++;
      }
      c = buf[++i];
    }
    // Remove trailing ':'
    buf[i - 1] = '\0';
    args[2] = buf;
    // printf("parsed buf , paramCount = %d, args = %s\n", paramCount, buf);
    if (rrd_update(3, args) != 0)
      fprintf(stderr, rrd_get_error());
    rrd_clear_error();
  }

  close(sockfd);
  return 0;
}
