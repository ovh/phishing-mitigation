#ifndef __ofp_uri_list_H__
#define __ofp_uri_list_H__

#define OFP_URI_LIST_POOL_CAPACITY 100000
#define OFP_URI_LIST_ENTRY_POOL_CAPACITY 200000

typedef struct _ofp_uri_list_entry
{
  char* uri;
#if REGEX
  ovh_regex_t* regex;
#endif
  struct _ofp_uri_list_entry* next;
  struct _ofp_uri_list_entry* mp_next;
} ofp_uri_list_entry_t;

typedef struct _ofp_uri_list
{
  ofp_uri_list_entry_t* head;
  ofp_uri_list_entry_t* tail;
  int count;
  ovh_mempool* entryPool;

  struct _ofp_uri_list* mp_next;
} ofp_uri_list_t;

extern ovh_mempool *ofp_uri_list_pool;
extern ovh_mempool *ofp_uri_list_entry_pool;

void ofp_uri_list_alloc_shared(tmc_alloc_t *alloc);
void ofp_uri_list_free_shared();

//List
ovh_mempool* ofp_uri_list_new_pool(uint32_t capacity, tmc_alloc_t *alloc);
ofp_uri_list_t* ofp_uri_list_new();
ofp_uri_list_t* ofp_uri_list_new_from(ovh_mempool* listPool, ovh_mempool* entryPool);
ofp_uri_list_t* ofp_uri_list_clone(ofp_uri_list_t* list);
void ofp_uri_list_copy(ofp_uri_list_t* dst, ofp_uri_list_t* src);
void ofp_uri_list_free_elements(ofp_uri_list_t* list);
void ofp_uri_list_free_from(ofp_uri_list_t* list, ovh_mempool* listPool);
void ofp_uri_list_free(ofp_uri_list_t* list);

//Entry
ovh_mempool* ofp_uri_list_entry_new_pool(uint32_t capacity, tmc_alloc_t *alloc);
ofp_uri_list_entry_t* ofp_uri_list_entry_new(ofp_uri_list_t* list);
void ofp_uri_list_entry_copy(ofp_uri_list_entry_t* dst, ofp_uri_list_entry_t* src);
ofp_uri_list_entry_t* ofp_uri_list_entry_add_uri(ofp_uri_list_t* list, char* uri);
#if REGEX
ofp_uri_list_entry_t* ofp_uri_list_entry_add_regex(ofp_uri_list_t* list, ovh_regex_t* regex);
#endif
int ofp_uri_list_entry_add(ofp_uri_list_t* list, ofp_uri_list_entry_t* entry);


#endif //__ofp_uri_list_H__
