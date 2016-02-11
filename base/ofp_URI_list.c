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

#include "ovh_common.h"
#include "ofp_URI_list.h"


ovh_mempool* ofp_uri_list_pool = NULL;
ovh_mempool* ofp_uri_list_entry_pool = NULL;

void ofp_uri_list_alloc_shared(tmc_alloc_t *alloc)
{
  OVH_ASSERT(ofp_uri_list_pool == NULL);
  ofp_uri_list_pool = ofp_uri_list_new_pool(OFP_URI_LIST_POOL_CAPACITY, alloc);
  OVH_ASSERT(ofp_uri_list_entry_pool == NULL);
  ofp_uri_list_entry_pool = ofp_uri_list_entry_new_pool(OFP_URI_LIST_ENTRY_POOL_CAPACITY, alloc);
}

void ofp_uri_list_free_shared()
{
  OVH_MEMPOOL_DISCARD_SHARED(ofp_uri_list_pool);
  OVH_MEMPOOL_DISCARD_SHARED(ofp_uri_list_entry_pool);
}
////////////////////////////////////////////////////////////////////////////////
///
///                                 List
///
////////////////////////////////////////////////////////////////////////////////

static int ofp_uri_list_init(ofp_uri_list_t* list, ovh_mempool* entryPool)
{
  OVH_ASSERT(list != NULL);
  list->head = NULL;
  list->tail = NULL;
  list->count = 0;
  list->entryPool = entryPool;

  return 1;
}

ovh_mempool* ofp_uri_list_new_pool(uint32_t capacity, tmc_alloc_t *alloc)
{
  ovh_mempool* listPool;
  OVH_MEMPOOL_CREATE_SHARED(listPool, ofp_uri_list_t, capacity, alloc);
  return listPool;
}

ofp_uri_list_t* ofp_uri_list_clone(ofp_uri_list_t* list)
{
  OVH_ASSERT(list != NULL);
  ofp_uri_list_t* listClone = ofp_uri_list_new();
  ofp_uri_list_copy(listClone, list);

  return listClone;
}

void ofp_uri_list_copy(ofp_uri_list_t* dstList, ofp_uri_list_t* srcList)
{
  OVH_ASSERT(dstList != NULL);
  OVH_ASSERT(srcList != NULL);
  ofp_uri_list_entry_t* entry = srcList->head;
  while(entry != NULL)
  {
    ofp_uri_list_entry_t* entryClone = ofp_uri_list_entry_new(dstList);
    ofp_uri_list_entry_copy(entryClone, entry);
    entry = entry->next;
  }
}

ofp_uri_list_t* ofp_uri_list_new_from(ovh_mempool* listPool, ovh_mempool* entryPool)
{
  OVH_ASSERT(listPool != NULL);
  OVH_ASSERT(entryPool != NULL);
  ofp_uri_list_t* list = NULL;
  OVH_MEMPOOL_ALLOC_ZEROED(*listPool, list);
  ofp_uri_list_init(list, entryPool);
  return list;
}

ofp_uri_list_t* ofp_uri_list_new()
{
  return ofp_uri_list_new_from(ofp_uri_list_pool, ofp_uri_list_entry_pool);
}

void ofp_uri_list_free(ofp_uri_list_t* list)
{
  ofp_uri_list_free_from(list, ofp_uri_list_pool);
}

void ofp_uri_list_free_from(ofp_uri_list_t* list, ovh_mempool* listPool)
{
  ofp_uri_list_free_elements(list);
  OVH_MEMPOOL_FREE(*listPool, list);
}

void ofp_uri_list_free_elements(ofp_uri_list_t* list)
{
  OVH_ASSERT(list != NULL);
  OVH_ASSERT(list->entryPool != NULL);

  ofp_uri_list_entry_t* entry = list->head;
  while(entry != NULL)
  {
    if(entry->uri != NULL)
    {
      OVH_FREE(entry->uri);
    }
#if REGEX
    if(entry->regex != NULL)
    {
      ovh_regex_free(entry->regex);
      entry->regex = NULL;
    }
#endif
    OVH_MEMPOOL_FREE(*list->entryPool, entry);
    entry = entry->next;
  }
  list->head = NULL;
  list->tail = NULL;
  list->count = 0;
}

////////////////////////////////////////////////////////////////////////////////
///
///                                 Entry
///
////////////////////////////////////////////////////////////////////////////////

ovh_mempool* ofp_uri_list_entry_new_pool(uint32_t capacity, tmc_alloc_t *alloc)
{
  ovh_mempool* entryPool;
  OVH_MEMPOOL_CREATE_SHARED(entryPool, ofp_uri_list_entry_t, capacity, alloc);
  return entryPool;
}


ofp_uri_list_entry_t* ofp_uri_list_entry_new(ofp_uri_list_t* list)
{
  OVH_ASSERT(list != NULL);
  OVH_ASSERT(list->entryPool != NULL);
  ofp_uri_list_entry_t* entry = NULL;
  OVH_MEMPOOL_ALLOC_ZEROED(*list->entryPool, entry);
  ofp_uri_list_entry_add(list, entry);
  return entry;
}

int ofp_uri_list_entry_add(ofp_uri_list_t* list, ofp_uri_list_entry_t* entry)
{
  OVH_ASSERT(list != NULL);
  OVH_ASSERT(entry != NULL);
  OVH_ASSERT(list->entryPool != NULL);
  if(list->head == NULL)
  {
    OVH_ASSERT(list->tail == NULL);
    list->head = list->tail = entry;
    list->count = 1;
  }
  else
  {
    OVH_ASSERT(list->tail != NULL);
    OVH_ASSERT(list->tail->next == NULL);
    list->tail->next = entry;
    list->tail = entry;
    list->count++;
  }
  return 1;
}

ofp_uri_list_entry_t* ofp_uri_list_entry_add_uri(ofp_uri_list_t* list, char* uri)
{
  OVH_ASSERT(list != NULL);
  ofp_uri_list_entry_t* entry = ofp_uri_list_entry_new(list);
  entry->uri = uri;
  return entry;
}

#if REGEX
ofp_uri_list_entry_t* ofp_uri_list_entry_add_regex(ofp_uri_list_t* list, ovh_regex_t* regex)
{
  OVH_ASSERT(list != NULL);
  ofp_uri_list_entry_t* entry = ofp_uri_list_entry_new(list);
  entry->regex = regex;
  return entry;
}
#endif

void ofp_uri_list_entry_copy(ofp_uri_list_entry_t* dst, ofp_uri_list_entry_t* src)
{
  OVH_ASSERT(dst != NULL);
  OVH_ASSERT(src != NULL);

  if(src->uri != NULL)
  {
    dst->uri = strdup(src->uri);
  }
  else
  {
    dst->uri = NULL;
  }
#if REGEX
  if(src->regex != NULL)
  {
    dst->regex = ovh_regex_clone(src->regex);
  }
  else
  {
    dst->regex = NULL;
  }
#endif

}


