#ifndef __OFP_PHISH_TARGET_IP_H__
#define __OFP_PHISH_TARGET_IP_H__

#include "uthash.h"
#include "ovh_mempool.h"

extern ovh_mempool *phish_target_ip_mempool;
#define PHISH_TARGET_IP_MEMPOOL_SIZE 100000


//TODO remplacer ip_port_tuple par une struct packed :
/*
typedef struct
{
  uint32_t ip;
  uint16_t port;
} __attribute__((packed)) ofp_phish_target_ip_key;
*/

//=======================================================================================================
// Internal struct describing a target
//=======================================================================================================
typedef struct _ofp_phish_target_ip
{
  ip_port_tuple ipPort; //Target Ip and port
  UT_hash_handle hh;
  struct _ofp_phish_target_ip *mp_next;
} ofp_phish_target_ip_t;


//=======================================================================================================
// Init
//=======================================================================================================
void ofp_phish_target_ip_alloc_shared(tmc_alloc_t *alloc);
void ofp_phish_target_ip_free_shared();

//=======================================================================================================
// Helpers
//=======================================================================================================
static INLINE ofp_phish_target_ip_t* _ofp_phish_target_ip_new()
{
  OVH_ASSERT(phish_target_ip_mempool != NULL);

  ofp_phish_target_ip_t* data = NULL;
  OVH_MEMPOOL_ALLOC_ZEROED(*phish_target_ip_mempool, data);
  return data;
}

static INLINE ofp_phish_target_ip_t* ofp_phish_target_ip_new_init(ip_port_tuple ipPort)
{
  ofp_phish_target_ip_t* data = _ofp_phish_target_ip_new();
  data->ipPort = ipPort;
  return data;
}



#endif //__OFP_PHISH_TARGET_IP_H__
