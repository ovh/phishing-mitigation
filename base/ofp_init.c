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
#include <unistd.h>
#include "ofp.h"
#include "ofp_init.h"
#include "uthash.h"
#include "ovh_mempool.h"
#include "ofp_URI_list.h"
#include "ofp_phish_desc_ht.h"
#include "ofp_phish_target_host_ht.h"
#include "ofp_phish_target_ip_ht.h"
#include "ofp_config_ip.h"
#include "ofp_event_http_match.h"

char ofp_host_name[256];

void ofp_init(int workSize, size_t event_pool_size)
{
  PRINT_D3("ofp_init(workSize=%d)\n", workSize);
  ofp_phish_desc_ht_init();
  ofp_phish_target_by_host_init(workSize);
  ofp_phish_target_by_ip_init(workSize);
  config_ip_init();
  ofp_event_http_match_init(event_pool_size);
  int result = gethostname(ofp_host_name, sizeof(ofp_host_name));
  OVH_ASSERT(result == 0);
}

void ofp_close()
{
  ofp_event_http_match_close();
  config_ip_close();
  ofp_phish_target_by_ip_close();
  ofp_phish_target_by_host_close();
  ofp_phish_desc_ht_close();
  PRINT_D3("ofp_close()\n");
}

void ofp_init_alloc_shared(tmc_alloc_t *alloc)
{
  PRINT_D3("ofp_init_alloc_shared()\n");
  ofp_phish_desc_alloc_shared(alloc);
  ofp_phish_target_alloc_shared(alloc);
  ofp_phish_target_ip_alloc_shared(alloc);
#if REGEX
  ovh_regex_alloc_shared(alloc);
#endif
  ofp_uri_list_alloc_shared(alloc);
}

void ofp_free_shared()
{
  PRINT_D3("ofp_free_shared()\n");
  ofp_phish_desc_free_shared();
  ofp_phish_target_free_shared();
#if REGEX
  ovh_regex_free_shared();
#endif
  ofp_uri_list_free_shared();
  ofp_phish_target_ip_free_shared();
}


#define OFP_LOG_FLAG(__flag) printf("=== %s = %d\n", #__flag, __flag);

void ofp_log_startup()
{
  struct tm *locTime = localtime(&(ovh_global_cur_time.tv_sec));
  static char dateStr[64];
  strftime(dateStr, 64, "%c", locTime);

  printf("========================================================\n");
  printf("===\n");
  printf("=== Started at [%s]\n", dateStr);
  printf("===\n");
  printf("========================================================\n");
  printf("===\n");
  OFP_LOG_FLAG(DEBUG);
  OFP_LOG_FLAG(REGEX);
  OFP_LOG_FLAG(SOCKET);
  OFP_LOG_FLAG(MODE_VLAN);
  OFP_LOG_FLAG(OFP_PROFILING);
  OFP_LOG_FLAG(OFP_LOOP_STATISTICS);
  OFP_LOG_FLAG(OFP_SYSLOG);
  OFP_LOG_FLAG(OVH_HASH_STATS);
  OFP_LOG_FLAG(OVH_LOG_ALLOC);
  OFP_LOG_FLAG(OVH_MEMPOOL_HUGEPAGES);
  OFP_LOG_FLAG(OVH_MEMPOOL_DEBUG);
  printf("===\n");
  printf("========================================================\n");

}

