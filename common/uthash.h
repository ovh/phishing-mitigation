#ifndef __UTHASH_WRAPPER_H__
#define __UTHASH_WRAPPER_H__


#if 1

#define OVH_HASH_COMPUTE_STATS(hash) \
  HASH_COMPUTE_STATS(hash)

#define OVH_HASH_CLEAR(hash) \
  HASH_CLEAR(hash)

#define OVH_HASH_ITER(hash,el,tmp) \
  HASH_ITER(hh,(hash)->head,el,tmp)

#define OVH_HASH_CHAIN_COUNT(hash, idx) \
  HASH_CHAIN_COUNT(hash, idx)

#define OVH_HASH_NUM_BUCKETS(hash) \
  (hash)->tbl.num_buckets

#define OVH_HASH_USAGE(hash) \
  HASH_USAGE(hash)

#define OVH_HASH_FSCK(hash) \
  HASH_FSCK(hh, hash)

#define OVH_HASH_INIT(hash, nb_buckets, entry_struct_name) \
  HASH_INIT(hash, nb_buckets, entry_struct_name)

#define OVH_HASH_INIT_WITH(hash, nb_buckets, entry_struct_name, allocator, ...) \
  HASH_INIT_WITH(hash, nb_buckets, entry_struct_name, allocator, __VA_ARGS__)

#define OVH_HASH_DISCARD(hash) \
  HASH_DISCARD(hash)

#define OVH_HASH_DEL(hash,delptr) \
  HASH_DEL(hash,delptr)

#define OVH_HASH_COUNT(hash) \
  HASH_COUNT(hash)

#define OVH_HASH_FIND_STR(hash,findstr,fieldname,out) \
    HASH_FIND_STR(hash,findstr,fieldname,out)

#define OVH_HASH_FIND_STR2(hash,findstr,fieldname, keylen,out)  \
    HASH_FIND(hash,findstr,fieldname[0],keylen,out)

#define OVH_HASH_ADD_STR(hash,strfield,add) \
    HASH_ADD_STR(hash,strfield,add)

#define OVH_HASH_FIND(hash,keyptr,key_fieldname,keylen,out) \
    HASH_FIND(hash,keyptr,key_fieldname,keylen,out)

#define OVH_HASH_ADD_KEYPTR(hash,keyptr,keylen_in,add)  \
    HASH_ADD_KEYPTR(hash,keyptr,keylen_in,add)

#include "uthash_ovh.h"

#else

#define OVH_HASH_COMPUTE_STATS(hash) \
do {                                                    \
}while(0)

#define OVH_HASH_CLEAR(hash) \
  HASH_CLEAR(hh, (hash)->head)

#define OVH_HASH_ITER(hash,el,tmp) \
  HASH_ITER(hh,(hash)->head,el,tmp)

#define HASH_CHAIN_COUNT(hash, idx) \
  -1

#define OVH_HASH_NUM_BUCKETS(hash) \
  ((hash)->head == NULL ? 0 : (hash)->head->hh.tbl->num_buckets)

#define OVH_HASH_USAGE(hash) \
  ((hash)->head == NULL ? 0 : (double)(hash)->head->hh.tbl->num_items / (double)(hash)->head->hh.tbl->num_buckets)

#define OVH_HASH_FSCK(hash) \
  HASH_FSCK(hh, (hash)->head)

#define OVH_HASH_INIT(hash, nb_buckets, struct_name)    \
do {                                                    \
}while(0)

#define OVH_HASH_DISCARD(hash) \
do {                                                    \
}while(0)

#define OVH_HASH_DEL(hash,delptr) \
  HASH_DEL((hash)->head,delptr)

#define OVH_HASH_COUNT(hash) \
  HASH_COUNT((hash)->head)

#define OVH_HASH_FIND_STR(hash,findstr,fieldname,out) \
    HASH_FIND(hh, (hash)->head, findstr, strlen((findstr)), out)

#define OVH_HASH_FIND_STR2(hash,findstr,fieldname, keylen,out)  \
    HASH_FIND(hh, (hash)->head, findstr, keylen, out)

#define OVH_HASH_ADD_STR(hash,strfield,add) \
    HASH_ADD_KEYPTR(hh, (hash)->head, (add)->strfield, strlen((add)->strfield), add);

#define OVH_HASH_FIND(hash,keyptr,key_fieldname,keylen,out) \
    HASH_FIND(hh, (hash)->head, keyptr, keylen, out)

#define OVH_HASH_ADD_KEYPTR(hash,keyptr,keylen_in,add)  \
    HASH_ADD_KEYPTR(hh, (hash)->head, keyptr, keylen_in, add);

#include "uthash_original.h"

#endif

#endif //__UTHASH_WRAPPER_H__