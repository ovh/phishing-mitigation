#ifndef __OFP_PHISH_TARGET_H__
#define __OFP_PHISH_TARGET_H__

#include "uthash.h"
#include "ovh_mempool.h"
#include "ofp_URI_list.h"

extern ovh_mempool *phish_target_mempool;
#define PHISH_TARGET_MEMPOOL_SIZE 100000

typedef enum { TargetError = -1, TargetUnknown = 0, TargetURI = 1, TargetPattern = 2 } target_type;

target_type str_to_target_type(const char* target_type_str);


//=======================================================================================================
// Internal struct describing a target
//=======================================================================================================
typedef struct _ofp_phish_target_host
{
  char* host;           //Host to monitor
  ofp_uri_list_t* uriList;  //URIs to match
  UT_hash_handle hh;
  struct _ofp_phish_target_host *mp_next;
} ofp_phish_target_host_t;


//=======================================================================================================
// Init
//=======================================================================================================
void ofp_phish_target_alloc_shared(tmc_alloc_t *alloc);
void ofp_phish_target_free_shared();

//=======================================================================================================
// Helpers
//=======================================================================================================
static INLINE ofp_phish_target_host_t* _ofp_phish_target_new_from(ovh_mempool* targetPool, ovh_mempool* listPool, ovh_mempool* listEntryPool)
{
  OVH_ASSERT(targetPool != NULL);
  OVH_ASSERT(listPool != NULL);
  OVH_ASSERT(listEntryPool != NULL);

  ofp_phish_target_host_t* data = NULL;
  OVH_MEMPOOL_ALLOC_ZEROED(*targetPool, data);
  if (data != NULL)
  {
    data->uriList = ofp_uri_list_new_from(listPool, listEntryPool);
  }
  return data;
}

static INLINE ofp_phish_target_host_t* _ofp_phish_target_new_empty()
{
  return _ofp_phish_target_new_from(phish_target_mempool, ofp_uri_list_pool, ofp_uri_list_entry_pool);
}

static INLINE ofp_phish_target_host_t* ofp_phish_target_new_dup(char* host)
{
  ofp_phish_target_host_t* data = _ofp_phish_target_new_empty();
  data->host = strdup(host);
  return data;
}



#endif //__OFP_PHISH_TARGET_H__
