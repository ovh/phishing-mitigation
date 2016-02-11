#ifndef __OFP_PHISH_DESC_HT_H__
#define __OFP_PHISH_DESC_HT_H__

#include "uthash.h"
#include "ovh_mempool.h"
#include "ofp_phish_desc.h"

typedef struct
{
  tmc_spin_mutex_t lock;
  int dirty;
  ofp_phish_desc_t *head;
  UT_hash_table tbl; /* uthash needed */
} ofp_phish_desc_hash_table_t;

typedef struct
{
  ofp_phish_desc_hash_table_t* hash;
} ofp_phish_desc_hash_table_locked_t;

#define PHISH_DESC_BUCKET_SIZE (32*1024)


//=======================================================================================================
// Memory allocated/used
//=======================================================================================================
uint32_t ofp_phish_desc_ht_mem_allocated();
uint32_t ofp_phish_desc_ht_mem_used();
//=======================================================================================================


//=======================================================================================================
// Init
//=======================================================================================================
void ofp_phish_desc_ht_init();
void ofp_phish_desc_ht_close();

//=======================================================================================================


//=======================================================================================================
// Helpers
//=======================================================================================================

static INLINE void ofp_phish_desc_ht_free_elements(ofp_phish_desc_hash_table_locked_t locked)
{
  ofp_phish_desc_hash_table_t* hash = locked.hash;

  ofp_phish_desc_t *desc=NULL, *tmp=NULL;
  OVH_HASH_ITER(hash, desc, tmp)
  {
    OVH_FREE(desc->data);
    OVH_HASH_DEL(hash, desc);
    OVH_MEMPOOL_FREE(*phish_desc_mempool, desc);
  }
  OVH_ASSERT(OVH_HASH_COUNT(hash) == 0);
  OVH_HASH_CLEAR(hash); //reset stats
}

static INLINE ofp_phish_desc_hash_table_locked_t ofp_phish_desc_ht_lock(ofp_phish_desc_hash_table_t* hash)
{
  tmc_spin_mutex_lock(&(hash->lock));
  ofp_phish_desc_hash_table_locked_t res = {
    .hash = hash,
  };
  return res;
}

static INLINE void ofp_phish_desc_ht_unlock(ofp_phish_desc_hash_table_locked_t locked)
{
  tmc_spin_mutex_unlock(&(locked.hash->lock));
}

static INLINE ofp_phish_desc_t* ofp_phish_desc_ht_find2(ofp_phish_desc_hash_table_locked_t locked, const char* descStr, uint32_t descStrLength)
{
  ofp_phish_desc_hash_table_t* hash = locked.hash;
  ofp_phish_desc_t* entry = NULL;
  OVH_HASH_FIND_STR2(hash, descStr, data, descStrLength, entry);
  return entry;
}

static INLINE ofp_phish_desc_t* ofp_phish_desc_ht_find(ofp_phish_desc_hash_table_locked_t locked, const char* descStr)
{
  return ofp_phish_desc_ht_find2(locked, descStr, strlen(descStr));
}

static INLINE ofp_phish_desc_t* _ofp_phish_desc_ht_insert_entry(ofp_phish_desc_hash_table_locked_t locked, ofp_phish_desc_t* desc)
{
  OVH_ASSERT(desc != NULL);
  OVH_ASSERT(desc->data != NULL);

  ofp_phish_desc_hash_table_t* hash = locked.hash;
  ofp_phish_desc_t* entry = NULL;
#if DEBUG
  OVH_HASH_FIND_STR(hash, desc->data, data, entry);
  OVH_ASSERT(entry == NULL);
#endif
  entry = desc;
  OVH_HASH_ADD_STR(hash, data, entry);
  return entry;
}

static INLINE int ofp_phish_desc_ht_insert2(ofp_phish_desc_hash_table_locked_t locked, const char* descStr, uint32_t strLen)
{
  ofp_phish_desc_t* desc = ofp_phish_desc_new_dup(descStr, strLen);
  _ofp_phish_desc_ht_insert_entry(locked, desc);
  return 1;
}

static INLINE int ofp_phish_desc_ht_insert(ofp_phish_desc_hash_table_locked_t locked, const char* descStr)
{
  return ofp_phish_desc_ht_insert2(locked, descStr, strlen(descStr));
}

//Return nb of entry inserted
// 0 = update
// 1 = insert
// < 0 if error
static INLINE int ofp_phish_desc_ht_upsert2(ofp_phish_desc_hash_table_locked_t locked, const char* descStr, uint32_t strLen)
{
  ofp_phish_desc_t* desc = ofp_phish_desc_ht_find2(locked, descStr, strLen);
  if(desc != NULL)
  {
    //nothing to do, since we found it, data contents are equal
    return 0;
  }
  else
  {
    return ofp_phish_desc_ht_insert2(locked, descStr, strLen);
  }

  return -1;
}

static INLINE int ofp_phish_desc_ht_upsert(ofp_phish_desc_hash_table_locked_t locked, const char* descStr)
{
  return ofp_phish_desc_ht_upsert2(locked, descStr, strlen(descStr));
}

//Return nb of entry deleted
// 0 = no present
// 1 = present and deleted
// < 0 if error
static INLINE int ofp_phish_desc_ht_free2(ofp_phish_desc_hash_table_locked_t locked, const char* descStr, uint32_t strLen)
{
  ofp_phish_desc_hash_table_t* hash = locked.hash;

  ofp_phish_desc_t *desc = ofp_phish_desc_ht_find2(locked, descStr, strLen);
  if(desc== NULL)
  {
    return 0;
  }

  OVH_FREE(desc->data);
  OVH_HASH_DEL(hash, desc);
  OVH_MEMPOOL_FREE(*phish_desc_mempool, desc);
  return 1;
}

static INLINE int ofp_phish_desc_ht_free(ofp_phish_desc_hash_table_locked_t locked, const char* descStr)
{
  return ofp_phish_desc_ht_free2(locked, descStr, strlen(descStr));
}

//=======================================================================================================





#endif //__OFP_PHISH_DESC_HT_H__
