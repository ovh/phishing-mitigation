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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "ovh_common.h"
#include "ovh_tools.h"
#include "ovh_log.h"

void inplace_string_set(inplace_string_t* inPlaceString, char* str)
{
  inPlaceString->data = str;
  inPlaceString->length = strlen(str);
}


// The current time, regularly updated by the GC thread
struct timeval ovh_global_cur_time;

int _parse_ip_internal(const char *str, int network_byte_order, ip_port_tuple* result)
{
  uint8_t tmp[4];
  char* dupStr = strdup(str);
  char *strTmp = strtok(dupStr, ".");
  for(int i=0; i<4; i++)
  {
    if (strTmp == NULL)
    {
      PRINT_ERR("Error parsing ip : %s\n", str);
      OVH_FREE(dupStr);
      return 0;
    }
    errno = 0;
    tmp[i] = strtol(strTmp,NULL,0);
    if(errno != 0)
    {
      PRINT_ERR("Error calling strtol for str=%s -- %s\n", str, strerror(errno));
      OVH_FREE(dupStr);
      return 0;
    }
    strTmp = strtok(NULL, ".");
  }

  if (network_byte_order)
    result->ip = ((uint32_t)tmp[3]) << 24 | tmp[2] << 16 | tmp[1] << 8 | tmp[0];
  else
    result->ip = ((uint32_t)tmp[0]) << 24 | tmp[1] << 16 | tmp[2] << 8 | tmp[3];

  OVH_FREE(dupStr);
  return 1;
}

int parse_host_with_port(char *inOutStr, int* port)
{
  OVH_ASSERT(inOutStr != NULL);
  *port = HTTP_HOSTNAME_DEFAULT_PORT;

  char* separator = strchr(inOutStr, ':');

  if (separator == NULL)
  {
    return 1;
  }

  const char* portPart = separator + 1;
  PRINT_D5("portPart = %s\n", portPart);
  *port = atoi(portPart);

  //normalize "host:80" to "host"
  if((*port) == HTTP_HOSTNAME_DEFAULT_PORT)
  {
    separator[0] = '\0';
  }

  //for all other ports we keep "host:port" string

  return 1;
}

int parse_ip(const char *str, int network_byte_order, ip_port_tuple* result)
{
  memset(result, 0, sizeof(ip_port_tuple)); //reset value
  if (strchr(str, '.') == NULL)
  {
    PRINT_ERR("Error parsing IP %s\n", str);
    return 0;
  }

  char* separator = strchr(str, ':');
  char* ipPart = NULL;
  char* portPart = NULL;

  if(separator != NULL)
  {
    int ipLen =  separator - str;
    ipPart = strndup(str, ipLen);
    portPart = strndup(separator + 1, strlen(str) - (ipLen + 1));
  }

  int ok = _parse_ip_internal(ipPart != NULL ? ipPart : str, network_byte_order, result);

  result->port = HTTP_HOSTNAME_DEFAULT_PORT;
  if(portPart != NULL)
  {
    result->port = atoi(portPart);
  }

  if(ipPart != NULL) OVH_FREE(ipPart);
  if(portPart != NULL) OVH_FREE(portPart);

  return ok;
}

ip_address_t ip_to_struct(int ip)
{
  ip_address_t res = {0};
#if BIG_ENDIAN
  res.d = ip & 0xFF;
  res.c = (ip >> 8) & 0xFF;
  res.b = (ip >> 16) & 0xFF;
  res.a = (ip >> 24) & 0xFF;
#else
  TODO
#endif

  return res;
}
