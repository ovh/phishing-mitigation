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
#include "ofp.h"
#include "ofp_phish_target_ip.h"

ovh_mempool *phish_target_ip_mempool;

void ofp_phish_target_ip_alloc_shared(tmc_alloc_t *alloc)
{
  OVH_MEMPOOL_CREATE_SHARED(phish_target_ip_mempool, ofp_phish_target_ip_t, PHISH_TARGET_IP_MEMPOOL_SIZE, alloc);
}

void ofp_phish_target_ip_free_shared()
{
  OVH_MEMPOOL_DISCARD_SHARED(phish_target_ip_mempool);
}
