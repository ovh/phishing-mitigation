#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <tmc/task.h>
#include <tmc/alloc.h>
#include <tmc/cpus.h>

#include "ofp.h"
#include "ofp_phish.h"
#include "ofp_config_ip.h"

uint32_t phish_host_count = 0;          //How many different host name are in phish list
uint32_t phish_target_count = 0;        //How many different target url are in phish list

void phish_sync()
{
  ofp_phish_desc_hash_table_locked_t config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);

  if(config_desc_locked.hash->dirty)
  {
    PRINT_D5("phish_sync() config_desc_hash is dirty, updating workers...\n");
    int result = config_ip_target_parse_desc_ht(config_host_hash, config_ip_hash, config_desc_locked);
    OVH_ASSERT(result > 0);

    ofp_phish_target_host_ht_locked_t config_host_locked = ofp_phish_target_by_host_lock(config_host_hash);
    ofp_phish_target_ip_ht_locked_t config_ip_locked = ofp_phish_target_by_ip_lock(config_ip_hash);

    phish_fill_from(config_host_locked, config_ip_locked);

    ofp_phish_target_by_host_free_elements(config_host_locked);
    ofp_phish_target_by_host_unlock(config_host_locked);

    ofp_phish_target_by_ip_free_elements(config_ip_locked);
    ofp_phish_target_by_ip_unlock(config_ip_locked);

    config_ip_desc_save_file(config_desc_locked, config_ip_file_name);
  }
  config_desc_locked.hash->dirty = 0;
  ofp_phish_desc_ht_unlock(config_desc_locked);
}

void phish_fill_from(ofp_phish_target_host_ht_locked_t srcLocked, ofp_phish_target_ip_ht_locked_t byIpLocked)
{
  phish_host_count = OVH_HASH_COUNT(srcLocked.hash);
  PRINT_D5("phish_fill_from()\n");

  phish_target_count = 0;
  ofp_phish_target_host_t *target=NULL, *tmp=NULL;
  OVH_HASH_ITER(srcLocked.hash, target, tmp)
  {
      phish_target_count += target->uriList->count;
  }

  PRINT_D5("total host count = %d\n", phish_host_count);
  PRINT_D5("total url count = %d\n", phish_target_count);

#if DEBUG
  //log targets
  ofp_phish_target_host_t *target0=NULL, *tmp0=NULL;
  OVH_HASH_ITER(srcLocked.hash, target0, tmp0)
  {
    OVH_ASSERT(target0 != NULL);
    OVH_ASSERT(target0->host != NULL);
    OVH_ASSERT(strlen(target0->host)>0);
    OVH_ASSERT(target0->uriList != NULL);
    PRINT_D5("For phishing target %s with %d uris\n", target0->host != NULL ? target0->host : "no hostName",  target0->uriList->count);
  }
#endif


  for (int rank = 0; rank < work_size; ++rank)
  {
    ofp_phish_target_host_ht_t* workerByHost = ofp_phish_target_by_host_get(rank);
    ofp_phish_target_host_ht_locked_t workerByHostLocked = ofp_phish_target_by_host_lock(workerByHost);

    ofp_phish_target_ip_ht_t* workerByIp = ofp_phish_target_by_ip_get(rank);
    ofp_phish_target_ip_ht_locked_t workerByIpLocked = ofp_phish_target_by_ip_lock(workerByIp);

    ofp_phish_target_by_host_copy(workerByHostLocked, srcLocked);
    ofp_phish_target_by_ip_copy(workerByIpLocked, byIpLocked);

    ofp_phish_target_by_ip_unlock(workerByIpLocked);
    ofp_phish_target_by_host_unlock(workerByHostLocked);

    //compute stats on worker 0
    if(rank == 0)
    {
      OVH_HASH_COMPUTE_STATS(workerByHost);
      OVH_HASH_COMPUTE_STATS(workerByIp);
    }
  }

}
