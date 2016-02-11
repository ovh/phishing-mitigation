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
#include <unistd.h>    //write

#include "ovh_common.h"

#include "ofp_socket_message_cb.h"
#include "ofp_config_ip.h"
#include "ofp_phish_desc.h"


int ofp_socket_message_cb(int sock, char* data)
{
  PRINT_D5("[Socket] received : '%s'\n", data);
  int error = 0;
  ssize_t writeRes = 0;

  if(strncmp(data, "list", strlen("list")) == 0)
  {
    char message[2000];
    ofp_phish_desc_hash_table_locked_t config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);
    snprintf(message, sizeof(message), "list start %d\n", OVH_HASH_COUNT(config_desc_locked.hash));
    writeRes = write(sock , message , strlen(message));
    error |= writeRes<0;

    ofp_phish_desc_t* desc=NULL;
    ofp_phish_desc_t* tmp=NULL;
    OVH_HASH_ITER(config_desc_hash, desc, tmp)
    {
      snprintf(message, sizeof(message), "%s\n", desc->data);
      writeRes = write(sock , message , strlen(message));
      error |= writeRes<0;
    }

    snprintf(message, sizeof(message), "list end\n");
    writeRes = write(sock , message , strlen(message));
    error |= writeRes<0;

    ofp_phish_desc_ht_unlock(config_desc_locked);

    if(error) return 0;
    return 1;
  }

  ofp_phish_desc_hash_table_locked_t config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);
  config_ip_desc_parse_delta_lines(config_desc_locked, data);
  ofp_phish_desc_ht_unlock(config_desc_locked);
  if(error) return 0;
  return 1;
}
