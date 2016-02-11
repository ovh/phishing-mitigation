#ifndef __OFP_PHISH_TARGET_BY_HOST_H__
#define __OFP_PHISH_TARGET_BY_HOST_H__

#include "uthash.h"
#include "ovh_mempool.h"
#include "ofp_phish_target_host.h"

typedef struct
{
  tmc_spin_mutex_t lock;
  ofp_phish_target_host_t *head;
  UT_hash_table tbl; /* uthash needed */
} ofp_phish_target_host_ht_t;

typedef struct
{
  ofp_phish_target_host_ht_t* hash;
} ofp_phish_target_host_ht_locked_t;

#define PHISH_TARGET_BY_HOST_BUCKET_SIZE (32*1024)

extern ofp_phish_target_host_ht_t* PhishTargetHostHashes;


//=======================================================================================================
// Init
//=======================================================================================================
void ofp_phish_target_by_host_init();
void ofp_phish_target_by_host_close();

//=======================================================================================================


//=======================================================================================================
// Helpers
//=======================================================================================================
int ofp_phish_target_by_host_copy(ofp_phish_target_host_ht_locked_t dst_locked, ofp_phish_target_host_ht_locked_t src_locked);

static INLINE ofp_phish_target_host_ht_t* ofp_phish_target_by_host_get(const int rank)
{
  return PhishTargetHostHashes+rank;
}

static INLINE void ofp_phish_target_by_host_free_elements(ofp_phish_target_host_ht_locked_t locked)
{
  ofp_phish_target_host_ht_t* hash = locked.hash;
  OVH_ASSERT(hash != NULL);

  ofp_phish_target_host_t *target=NULL, *tmp=NULL;
  OVH_HASH_ITER(hash, target, tmp)
  {
    ofp_uri_list_free(target->uriList);
    OVH_FREE(target->host);
    OVH_HASH_DEL(hash,target);
    OVH_MEMPOOL_FREE(*phish_target_mempool, target);
  }
  OVH_ASSERT(OVH_HASH_COUNT(hash) == 0);
  OVH_HASH_CLEAR(hash); //reset stats
}

static INLINE ofp_phish_target_host_ht_locked_t ofp_phish_target_by_host_lock(ofp_phish_target_host_ht_t* hash)
{
  tmc_spin_mutex_lock(&(hash->lock));
  ofp_phish_target_host_ht_locked_t res = {
    .hash = hash,
  };
  //tmc_spin_mutex_unlock(&(hash->lock));
  return res;
}

static INLINE void ofp_phish_target_by_host_unlock(ofp_phish_target_host_ht_locked_t locked)
{
  tmc_spin_mutex_unlock(&(locked.hash->lock));
}

static INLINE ofp_phish_target_host_t* ofp_phish_target_by_host_find2(ofp_phish_target_host_ht_locked_t locked, char* host, uint32_t hostLength)
{
  ofp_phish_target_host_ht_t* hash = locked.hash;
  OVH_ASSERT(hash != NULL);

  ofp_phish_target_host_t* data = NULL;
  OVH_HASH_FIND_STR2(hash, host, host, hostLength, data);
  return data;
}

static INLINE ofp_phish_target_host_t* ofp_phish_target_by_host_find(ofp_phish_target_host_ht_locked_t locked, char* host)
{
  return ofp_phish_target_by_host_find2(locked, host, strlen(host));
}

static INLINE ofp_phish_target_host_t* ofp_phish_target_by_host_insert(ofp_phish_target_host_ht_locked_t locked, ofp_phish_target_host_t* target)
{
  OVH_ASSERT(target->host != NULL);
  OVH_ASSERT(target->uriList != NULL);

  ofp_phish_target_host_ht_t* hash = locked.hash;
  OVH_ASSERT(hash != NULL);

  ofp_phish_target_host_t* data = NULL;
#if DEBUG
  OVH_HASH_FIND_STR(hash, target->host, host, data);
  OVH_ASSERT(data == NULL);
#endif
  data = target;
  OVH_HASH_ADD_STR(hash, host, data);
  return data;
}


//=======================================================================================================





#endif //__OFP_PHISH_TARGET_BY_HOST_H__
