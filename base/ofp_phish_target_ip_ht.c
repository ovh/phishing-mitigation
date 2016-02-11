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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ofp.h"
#include "ofp_phish_target_ip_ht.h"
#include "ofp_workers.h"

ofp_phish_target_ip_ht_t* PhishTargetIpHashes;
static int PhishTargetIpHashTableCount = 0;

//=======================================================================================================
// Init
//=======================================================================================================
void ofp_phish_target_by_ip_init(int workSize)
{
  PhishTargetIpHashTableCount = workSize;

  PhishTargetIpHashes = OVH_CALLOC(PhishTargetIpHashTableCount, sizeof(*PhishTargetIpHashes));
  if (PhishTargetIpHashes == NULL)
    TMC_TASK_DIE("Failed to allocate hash 'PhishTargetIpHashes'");
  for (int i = 0; i < PhishTargetIpHashTableCount; ++i)
  {
    OVH_HASH_INIT_WITH(&PhishTargetIpHashes[i], PHISH_TARGET_BY_IP_BUCKET_SIZE, ofp_phish_target_ip_t, OVH_HOMED_ALLOCATOR, i);
  }
}

void ofp_phish_target_by_ip_close()
{
  for (int i = 0; i < PhishTargetIpHashTableCount; ++i)
  {
    OVH_HASH_DISCARD(&PhishTargetIpHashes[i]);
  }
  OVH_FREE(PhishTargetIpHashes);
}
//=======================================================================================================

//=======================================================================================================
// Helper methods
//=======================================================================================================
//=======================================================================================================
int ofp_phish_target_by_ip_copy(ofp_phish_target_ip_ht_locked_t dst_locked, ofp_phish_target_ip_ht_locked_t src_locked)
{
  //this function can be called multiple times, so we need to free previously allocated memory
  ofp_phish_target_by_ip_free_elements(dst_locked);
  OVH_ASSERT(OVH_HASH_COUNT(dst_locked.hash) == 0); //all removed ?


  ofp_phish_target_ip_t *desc=NULL, *tmp=NULL;
  OVH_HASH_ITER(src_locked.hash, desc, tmp)
  {
    OVH_ASSERT(desc != NULL);
    ofp_phish_target_ip_t* targetCopy = ofp_phish_target_ip_new_init(desc->ipPort);
    ofp_phish_target_by_ip_insert(dst_locked, targetCopy);
  }

  ofp_phish_target_by_ip_unlock(dst_locked);

  OVH_ASSERT(OVH_HASH_COUNT(src_locked.hash) == OVH_HASH_COUNT(dst_locked.hash));

  return 1;
}


