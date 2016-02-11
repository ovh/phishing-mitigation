#ifndef __OFP_PHISH_DESC_H__
#define __OFP_PHISH_DESC_H__

#include "uthash.h"
#include "ovh_mempool.h"

extern ovh_mempool *phish_desc_mempool;
#define PHISH_DESC_MEMPOOL_SIZE 10000

//=======================================================================================================
// Internal struct
//=======================================================================================================
typedef struct _ofp_phish_desc
{
  char* data;
  UT_hash_handle hh;
  struct _ofp_phish_desc *mp_next;
} ofp_phish_desc_t;


//=======================================================================================================
// Init
//=======================================================================================================
void ofp_phish_desc_alloc_shared(tmc_alloc_t *alloc);
void ofp_phish_desc_free_shared();

//=======================================================================================================
// Helpers
//=======================================================================================================
static INLINE ofp_phish_desc_t* ofp_phish_desc_new()
{
  OVH_ASSERT(phish_desc_mempool != NULL);

  ofp_phish_desc_t* desc = NULL;
  OVH_MEMPOOL_ALLOC_ZEROED(*phish_desc_mempool, desc);
  if (desc != NULL)
  {
    desc->data = NULL;
  }
  return desc;
}

static INLINE ofp_phish_desc_t* ofp_phish_desc_new_dup(const char* descStr, uint32_t strLen)
{
  ofp_phish_desc_t* desc = ofp_phish_desc_new();
  desc->data = strndup(descStr, strLen); //must be free by ofp_phish_desc_ht_free_XXX

  return desc;
}



#endif //__OFP_PHISH_DESC_H__
