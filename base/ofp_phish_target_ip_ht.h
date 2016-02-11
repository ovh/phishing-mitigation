#ifndef __OFP_PHISH_TARGET_BY_IP_H__
#define __OFP_PHISH_TARGET_BY_IP_H__

#include "uthash.h"
#include "ovh_mempool.h"
#include "ofp_phish_target_ip.h"

typedef struct
{
  tmc_spin_mutex_t lock;
  ofp_phish_target_ip_t *head;
  UT_hash_table tbl; /* uthash needed */
} ofp_phish_target_ip_ht_t;

typedef struct
{
  ofp_phish_target_ip_ht_t* hash;
} ofp_phish_target_ip_ht_locked_t;

#define PHISH_TARGET_BY_IP_BUCKET_SIZE (32*1024)

extern ofp_phish_target_ip_ht_t* PhishTargetIpHashes;


//=======================================================================================================
// Init
//=======================================================================================================
void ofp_phish_target_by_ip_init();
void ofp_phish_target_by_ip_close();

//=======================================================================================================


//=======================================================================================================
// Helpers
//=======================================================================================================

int ofp_phish_target_by_ip_copy(ofp_phish_target_ip_ht_locked_t dst_locked, ofp_phish_target_ip_ht_locked_t src_locked);

static INLINE ofp_phish_target_ip_ht_t* ofp_phish_target_by_ip_get(const int rank)
{
  return PhishTargetIpHashes+rank;
}

static INLINE void ofp_phish_target_by_ip_free_elements(ofp_phish_target_ip_ht_locked_t locked)
{
  ofp_phish_target_ip_ht_t* hash = locked.hash;
  OVH_ASSERT(hash != NULL);

  ofp_phish_target_ip_t *target=NULL, *tmp=NULL;
  OVH_HASH_ITER(hash, target, tmp)
  {
    OVH_HASH_DEL(hash,target);
    OVH_MEMPOOL_FREE(*phish_target_ip_mempool, target);
  }
  OVH_ASSERT(OVH_HASH_COUNT(hash) == 0);
  OVH_HASH_CLEAR(hash); //reset stats
}

static INLINE ofp_phish_target_ip_ht_locked_t ofp_phish_target_by_ip_lock(ofp_phish_target_ip_ht_t* hash)
{
  tmc_spin_mutex_lock(&(hash->lock));
  ofp_phish_target_ip_ht_locked_t res = {
    .hash = hash,
  };
  return res;
}

static INLINE void ofp_phish_target_by_ip_unlock(ofp_phish_target_ip_ht_locked_t locked)
{
  tmc_spin_mutex_unlock(&(locked.hash->lock));
}

static INLINE ofp_phish_target_ip_t* ofp_phish_target_by_ip_find(ofp_phish_target_ip_ht_locked_t locked, ip_port_tuple ip_port)
{
  ofp_phish_target_ip_ht_t* hash = locked.hash;
  OVH_ASSERT(hash != NULL);

  ofp_phish_target_ip_t* data = NULL;
  OVH_HASH_FIND(hash, &ip_port, ipPort, sizeof(ip_port_tuple), data);
  return data;
}

static INLINE ofp_phish_target_ip_t* ofp_phish_target_by_ip_insert(ofp_phish_target_ip_ht_locked_t locked, ofp_phish_target_ip_t* target)
{
  OVH_ASSERT(target != NULL);
  ofp_phish_target_ip_ht_t* hash = locked.hash;
  OVH_ASSERT(hash != NULL);

  OVH_HASH_ADD_KEYPTR(hash, &target->ipPort.ip, sizeof(ip_port_tuple), target);
  return target;
}

static INLINE ofp_phish_target_ip_t* ofp_phish_target_by_ip_upsert(ofp_phish_target_ip_ht_locked_t locked, ip_port_tuple ip_port)
{
  ofp_phish_target_ip_ht_t* hash = locked.hash;
  OVH_ASSERT(hash != NULL);

  ofp_phish_target_ip_t* data = ofp_phish_target_by_ip_find(locked, ip_port);
  if(data != NULL)
  {
    //already exist
    return data;
  }

  data = ofp_phish_target_ip_new_init(ip_port);

  return ofp_phish_target_by_ip_insert(locked, data);
}


//=======================================================================================================





#endif //__OFP_PHISH_TARGET_BY_IP_H__
