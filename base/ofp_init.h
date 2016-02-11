#ifndef __OFP_INIT_H__
#define __OFP_INIT_H__

void ofp_init(int workSize, size_t event_pool_size);
void ofp_close();
void ofp_init_alloc_shared(tmc_alloc_t *alloc);
void ofp_free_shared();
void ofp_log_startup();

extern char ofp_host_name[256];


#endif //__OFP_INIT_H__
