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
#include "ofp_phish_target_host_ht.h"
#include "ofp_workers.h"

ofp_phish_target_host_ht_t* PhishTargetHostHashes;
static int PhishTargetHostHashTableCount = 0;


//=======================================================================================================
// Init
//=======================================================================================================
void ofp_phish_target_by_host_init(int workSize)
{
  PhishTargetHostHashTableCount = workSize;

  PhishTargetHostHashes = OVH_CALLOC(PhishTargetHostHashTableCount, sizeof(*PhishTargetHostHashes));
  if (PhishTargetHostHashes == NULL)
    TMC_TASK_DIE("Failed to allocate hash 'PhishTargetHostHashes'");

  for (int i = 0; i < PhishTargetHostHashTableCount; ++i)
  {
    OVH_HASH_INIT_WITH(&PhishTargetHostHashes[i], PHISH_TARGET_BY_HOST_BUCKET_SIZE, ofp_phish_target_host_t, OVH_HOMED_ALLOCATOR, i);
  }
}

void ofp_phish_target_by_host_close()
{
  for (int i = 0; i < PhishTargetHostHashTableCount; ++i)
  {
    OVH_HASH_DISCARD(&PhishTargetHostHashes[i]);
  }
  OVH_FREE(PhishTargetHostHashes);
}

//=======================================================================================================

//=======================================================================================================
// Helper methods
//=======================================================================================================
//=======================================================================================================

int ofp_phish_target_by_host_copy(ofp_phish_target_host_ht_locked_t dst_locked, ofp_phish_target_host_ht_locked_t src_locked)
{
  //this function can be called multiple times, so we need to free previously allocated memory
  ofp_phish_target_by_host_free_elements(dst_locked);
  OVH_ASSERT(OVH_HASH_COUNT(dst_locked.hash) == 0); //all removed ?


  ofp_phish_target_host_t *desc=NULL, *tmp=NULL;
  OVH_HASH_ITER(src_locked.hash, desc, tmp)
  {
    OVH_ASSERT(desc != NULL);
    OVH_ASSERT(desc->host != NULL);
    OVH_ASSERT(strlen(desc->host)>0);
    OVH_ASSERT(desc->uriList != NULL);

    ofp_phish_target_host_t* targetCopy = ofp_phish_target_new_dup(desc->host);

    ofp_uri_list_copy(targetCopy->uriList, desc->uriList);
    ofp_phish_target_by_host_insert(dst_locked, targetCopy);
  }

  OVH_ASSERT(OVH_HASH_COUNT(src_locked.hash) == OVH_HASH_COUNT(dst_locked.hash)); 

  return 1;
}

