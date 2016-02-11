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
#include "ofp_phish_desc_ht.h"
#include "ofp_workers.h"

//=======================================================================================================
// Memory usage
//=======================================================================================================
static uint32_t ofp_phish_desc_ht_base_mem_allocated = 0;

uint32_t ofp_phish_desc_ht_mem_allocated()
{
  if (!ofp_phish_desc_ht_base_mem_allocated)
  {
    ofp_phish_desc_ht_base_mem_allocated = 0
              + OVH_MEMPOOL_STATS_ALLOCATED(*phish_desc_mempool)
              ;
  }
  return ofp_phish_desc_ht_base_mem_allocated;
}

uint32_t ofp_phish_desc_ht_mem_used()
{
  return ofp_phish_desc_ht_base_mem_allocated
              - OVH_MEMPOOL_STATS_FREE(*phish_desc_mempool)
              ;
}


//=======================================================================================================
// Init
//=======================================================================================================
void ofp_phish_desc_ht_init(int workSize)
{
}

void ofp_phish_desc_ht_close()
{
}

//=======================================================================================================

//=======================================================================================================
// Helper methods
//=======================================================================================================
//=======================================================================================================
