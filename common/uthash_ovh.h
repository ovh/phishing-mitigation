/*
Copyright (c) 2003-2013, Troy D. Hanson     http://troydhanson.github.com/uthash/
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <string.h>   /* memcmp,strlen */
#include <stddef.h>   /* ptrdiff_t */
#include <stdlib.h>   /* exit() */
#include <math.h>     /* log2() */

#ifdef UTHASH_H
# undef HASH_FCN
#endif

#ifndef HASH_DEBUG
#define HASH_DEBUG 0
#endif

/* These macros use decltype or the earlier __typeof GNU extension.
   As decltype is only available in newer compilers (VS2010 or gcc 4.3+
   when compiling c++ source) this code uses whatever method is needed
   or, for VS2008 where neither is available, uses casting workarounds. */
#ifdef _MSC_VER         /* MS compiler */
#if _MSC_VER >= 1600 && defined(__cplusplus)  /* VS2010 or newer in C++ mode */
#define DECLTYPE(x) (decltype(x))
#else                   /* VS2008 or older (or VS2010 in C mode) */
#define NO_DECLTYPE
#define DECLTYPE(x)
#endif
#else                   /* GNU, Sun and other compilers */
#define DECLTYPE(x) (__typeof(x))
#endif

#ifdef NO_DECLTYPE
#define DECLTYPE_ASSIGN(dst,src)                                                 \
do {                                                                             \
  char **_da_dst = (char**)(&(dst));                                             \
  *_da_dst = (char*)(src);                                                       \
} while(0)
#else 
#define DECLTYPE_ASSIGN(dst,src)                                                 \
do {                                                                             \
  (dst) = DECLTYPE(dst)(src);                                                    \
} while(0)
#endif

/* a number of the hash function use uint32_t which isn't defined on win32 */
#ifdef _MSC_VER
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
#else
#include <inttypes.h>   /* uint32_t */
#endif

#define UTHASH_VERSION 1.9.8

#ifndef uthash_fatal
#define uthash_fatal(msg) exit(-1)        /* fatal error (out of memory,etc) */
#endif
#ifndef uthash_malloc
#define uthash_malloc(sz) OVH_MAP_MALLOC(sz)      /* malloc fcn                      */
#endif
#ifndef uthash_free
#define uthash_free(ptr,sz) OVH_FREE_MAP(ptr, sz)     /* free fcn                        */
#endif

#ifndef uthash_noexpand_fyi
#define uthash_noexpand_fyi(tbl)          /* can be defined to log noexpand  */
#endif
#ifndef uthash_expand_fyi
#define uthash_expand_fyi(tbl)            /* can be defined to log expands   */
#endif

/* initial number of buckets */
#define HASH_INITIAL_NUM_BUCKETS 32      /* initial number of buckets        */
#define HASH_INITIAL_NUM_BUCKETS_LOG2 5  /* lg2 of initial number of buckets */
#define HASH_BKT_CAPACITY_THRESH 10      /* expand when bucket count reaches */

/* calculate the element whose hash handle address is hhe */
#define ELMT_FROM_HH(tbl,hhp) ((void*)(((char*)(hhp)) - ((tbl)->hho)))

#define HASH_INIT_WITH(hash, nb_buckets, struct_name, allocator, ...)                                  \
do {                                                                              \
  UT_hash_bucket *buckets = allocator (nb_buckets, sizeof(UT_hash_bucket), __VA_ARGS__);              \
  if (!buckets)                                                       \
    tmc_task_die("Failed to allocate " #hash "->tbl.buckets");                    \
  (hash)->tbl.buckets = buckets;                                              \
  (hash)->tbl.num_buckets = nb_buckets;                                           \
  (hash)->tbl.log2_num_buckets = log2(nb_buckets);                                \
  (hash)->tbl.hho = offsetof(struct_name, hh);                                    \
  (hash)->tbl.signature = HASH_SIGNATURE;                                      \
} while(0)

#define HASH_INIT(hash, nb_buckets, struct_name)                                  \
do {                                                                              \
  HASH_INIT_WITH(hash, nb_buckets, struct_name, OVH_AUTO_PAGED_ALLOCATOR, __not_used);             \
} while(0)

#define HASH_DISCARD(hash)                                  \
do {                                                                              \
  if (!(hash)->tbl.buckets)                                                       \
    tmc_task_die("Failed to free " #hash "->tbl.buckets");                    \
  uthash_free((hash)->tbl.buckets, (hash)->tbl.num_buckets * sizeof(UT_hash_bucket));                                                      \
  (hash)->tbl.buckets = 0;                                                        \
  (hash)->tbl.num_buckets = 0;                                           \
  (hash)->tbl.log2_num_buckets = 0;                                \
} while(0)

#define HASH_FIND(hash,keyptr,key_fieldname,keylen,out)                                     \
do {                                                                             \
  int _hf_bkt=-1,_hf_hashv=-1;                                                    \
  HASH_FIND_HA(hash,keyptr,key_fieldname,keylen,out,_hf_bkt,_hf_hashv);          \
} while (0)

#define HASH_FIND_HA(hash,keyptr,key_fieldname,keylen,out,_hf_bkt,_hf_hashv)                \
do {                                                                             \
  out=NULL;                                                                      \
  if (_hf_bkt < 0)                                                          \
    HASH_FCN(keyptr,keylen, (hash)->tbl.num_buckets, _hf_hashv, _hf_bkt);   \
  if ((hash)->head) {                                                                    \
    if (HASH_BLOOM_TEST(&((hash)->tbl), _hf_hashv)) {                           \
      HASH_FIND_IN_BKT(&((hash)->tbl), (hash)->tbl.buckets[ _hf_bkt ],  \
                        keyptr,key_fieldname,keylen,out);                                      \
    }                                                                           \
  }                                                                              \
} while (0)

#ifdef HASH_BLOOM
#define HASH_BLOOM_BITLEN (1ULL << HASH_BLOOM)
#define HASH_BLOOM_BYTELEN (HASH_BLOOM_BITLEN/8) + ((HASH_BLOOM_BITLEN%8) ? 1:0)
#define HASH_BLOOM_MAKE(tbl)                                                     \
do {                                                                             \
  (tbl)->bloom_nbits = HASH_BLOOM;                                               \
  (tbl)->bloom_bv = (uint8_t*)uthash_malloc(HASH_BLOOM_BYTELEN);                 \
  if (!((tbl)->bloom_bv))  { uthash_fatal( "out of memory"); }                   \
  memset((tbl)->bloom_bv, 0, HASH_BLOOM_BYTELEN);                                \
  (tbl)->bloom_sig = HASH_BLOOM_SIGNATURE;                                       \
} while (0)

#define HASH_BLOOM_FREE(tbl)                                                     \
do {                                                                             \
  uthash_free((tbl)->bloom_bv, HASH_BLOOM_BYTELEN);                              \
} while (0)

#define HASH_BLOOM_BITSET(bv,idx) (bv[(idx)/8] |= (1U << ((idx)%8)))
#define HASH_BLOOM_BITTEST(bv,idx) (bv[(idx)/8] & (1U << ((idx)%8)))

#define HASH_BLOOM_ADD(tbl,hashv)                                                \
  HASH_BLOOM_BITSET((tbl)->bloom_bv, (hashv & (uint32_t)((1ULL << (tbl)->bloom_nbits) - 1)))

#define HASH_BLOOM_TEST(tbl,hashv)                                               \
  HASH_BLOOM_BITTEST((tbl)->bloom_bv, (hashv & (uint32_t)((1ULL << (tbl)->bloom_nbits) - 1)))

#else
#define HASH_BLOOM_MAKE(tbl)
#define HASH_BLOOM_FREE(tbl)
#define HASH_BLOOM_ADD(tbl,hashv)
#define HASH_BLOOM_TEST(tbl,hashv) (1)
#define HASH_BLOOM_BYTELEN 0
#endif

#define HASH_ADD_KEYPTR(hash,keyptr,keylen_in,add)                               \
do {                                                                             \
  int __ha_bkt=-1, __hf_hashv=-1;                                                \
  HASH_ADD_HA(hash, keyptr, keylen_in, add, __ha_bkt, __hf_hashv) ;              \
} while(0)

#define HASH_ADD(hash,fieldname,keylen_in,add)                                   \
do {                                                                             \
  int __ha_bkt=-1, __hf_hashv=-1;                                                \
  HASH_ADD_HA(hash,&((add)->fieldname),keylen_in,add,__ha_bkt,__hf_hashv) ;      \
} while(0)

#define HASH_REPLACE(hh,head,fieldname,keylen_in,add,replaced)                   \
do {                                                                             \
  replaced=NULL;                                                                 \
  HASH_FIND(hh,head,&((add)->fieldname),keylen_in,replaced);                     \
  if (replaced!=NULL) {                                                          \
     HASH_DELETE(hh,head,replaced);                                              \
  };                                                                             \
  HASH_ADD(hh,head,fieldname,keylen_in,add);                                     \
} while(0)

#define HASH_ADD_HA(hash,keyptr,keylen_in,add,_ha_bkt,_hf_hashv)                            \
do {                                                                             \
 if (_ha_bkt < 0)                                                          \
   HASH_FCN(keyptr,keylen_in, (hash)->tbl.num_buckets, _hf_hashv, _ha_bkt);   \
 (add)->hh.next = NULL;                                                          \
 if (!(hash)->head) {                                                                  \
    (hash)->head = (add);                                                                \
    (hash)->head->hh.prev = NULL;                                                      \
 } else {                                                                        \
    (hash)->tbl.tail->next = (add);                                          \
    (add)->hh.prev = ELMT_FROM_HH(&((hash)->tbl), (hash)->tbl.tail);         \
 }                                                                               \
 (hash)->tbl.num_items++;                                                    \
 (add)->hh.hashv = _hf_hashv;                                                    \
 (hash)->tbl.tail = &((add)->hh);                                            \
 HASH_ADD_TO_BKT((hash)->tbl.buckets[_ha_bkt],&(add)->hh);                   \
 HASH_BLOOM_ADD(&((hash)->tbl),(add)->hh.hashv);                                 \
 HASH_EMIT_KEY(hh,hash->head,keyptr,keylen_in);                                        \
 HASH_FSCK(hh, hash);                                                             \
} while(0)

#define HASH_TO_BKT( hashv, num_bkts, bkt )                                      \
do {                                                                             \
  bkt = ((hashv) & ((num_bkts) - 1));                                            \
} while(0)

/* delete "delptr" from the hash table.
 * "the usual" patch-up process for the app-order doubly-linked-list.
 * The use of _hd_hh_del below deserves special explanation.
 * These used to be expressed using (delptr) but that led to a bug
 * if someone used the same symbol for the head and deletee, like
 *  HASH_DELETE(hh,users,users);
 * We want that to work, but by changing the head (users) below
 * we were forfeiting our ability to further refer to the deletee (users)
 * in the patch-up process. Solution: use scratch space to
 * copy the deletee pointer, then the latter references are via that
 * scratch pointer rather than through the repointed (users) symbol.
 */
#define HASH_DELETE(hh,hash,delptr)                                              \
do {                                                                             \
    unsigned _hd_bkt;                                                            \
    struct UT_hash_handle *_hd_hh_del = &((delptr)->hh);                         \
    HASH_TO_BKT( _hd_hh_del->hashv, (hash)->tbl.num_buckets, _hd_bkt);   \
    if ( ((delptr)->hh.prev == NULL) && ((delptr)->hh.next == NULL) )  {         \
        (hash)->head = NULL;                                                       \
        (hash)->tbl.buckets[_hd_bkt].hh_head = NULL;                             \
        (hash)->tbl.buckets[_hd_bkt].count = 0;                                   \
    } else {                                                                     \
        if ((delptr) == ELMT_FROM_HH(&((hash)->tbl),(hash)->tbl.tail)) {     \
            (hash)->tbl.tail =                                               \
                (UT_hash_handle*)((ptrdiff_t)((delptr)->hh.prev) +               \
                (hash)->tbl.hho);                                            \
        }                                                                        \
        if ((delptr)->hh.prev) {                                                 \
            ((UT_hash_handle*)((ptrdiff_t)((delptr)->hh.prev) +                  \
                    (hash)->tbl.hho))->next = (delptr)->hh.next;             \
        } else {                                                                 \
            DECLTYPE_ASSIGN((hash)->head,(delptr)->hh.next);                             \
        }                                                                        \
        if (_hd_hh_del->next) {                                                  \
            ((UT_hash_handle*)((ptrdiff_t)_hd_hh_del->next +                     \
                    (hash)->tbl.hho))->prev =                                \
                    _hd_hh_del->prev;                                            \
        }                                                                        \
        HASH_DEL_IN_BKT(hh,(hash)->tbl.buckets[_hd_bkt], _hd_hh_del);        \
    }                                                                            \
    (hash)->tbl.num_items--;                                             \
    HASH_FSCK(hh, hash);                                                          \
} while (0)


/* convenience forms of HASH_FIND/HASH_ADD/HASH_DEL */
#define HASH_FIND_STR(hash,findstr,fieldname,out)                                          \
    HASH_FIND(hash,findstr,fieldname[0],strlen(findstr),out)
#define HASH_ADD_STR(hash,strfield,add)                                          \
    HASH_ADD(hash,strfield[0],strlen(add->strfield),add)
#define HASH_REPLACE_STR(head,strfield,add,replaced)                             \
  HASH_REPLACE(hh,head,strfield[0],strlen(add->strfield),add,replaced)
#define HASH_FIND_INT(head,findint,out)                                          \
    HASH_FIND(hh,head,findint,sizeof(int),out)
#define HASH_ADD_INT(head,intfield,add)                                          \
    HASH_ADD(hh,head,intfield,sizeof(int),add)
#define HASH_REPLACE_INT(head,intfield,add,replaced)                             \
    HASH_REPLACE(hh,head,intfield,sizeof(int),add,replaced)
#define HASH_FIND_PTR(head,findptr,out)                                          \
    HASH_FIND(hh,head,findptr,sizeof(void *),out)
#define HASH_ADD_PTR(head,ptrfield,add)                                          \
    HASH_ADD(hh,head,ptrfield,sizeof(void *),add)
#define HASH_REPLACE_PTR(head,ptrfield,add)                                      \
    HASH_REPLACE(hh,head,ptrfield,sizeof(void *),add,replaced)
#define HASH_DEL(hash,delptr)                                                    \
    HASH_DELETE(hh,hash,delptr)

/* HASH_FSCK checks hash integrity on every add/delete when HASH_DEBUG is true.
 * This is for uthash developer only; it compiles away if HASH_DEBUG is false or undefined.
 */
#if HASH_DEBUG
#define HASH_OOPS(...) do { fprintf(stderr,__VA_ARGS__); exit(-1); } while (0)
#define HASH_FSCK2(hh,head,tbl)                                                   \
do {                                                                             \
    unsigned _bkt_i;                                                             \
    unsigned _count, _bkt_count;                                                 \
    char *_prev;                                                                 \
    struct UT_hash_handle *_thh;                                                 \
    _count = 0;                                                              \
    for( _bkt_i = 0; _bkt_i < tbl.num_buckets; _bkt_i++) {       \
        _bkt_count = 0;                                                      \
        _thh = tbl.buckets[_bkt_i].hh_head;                      \
        _prev = NULL;                                                        \
        while (_thh) {                                                       \
           if (_prev != (char*)(_thh->hh_prev)) {                            \
               HASH_OOPS("invalid hh_prev %p, actual %p\n",                  \
                _thh->hh_prev, _prev );                                      \
           }                                                                 \
           _bkt_count++;                                                     \
           _prev = (char*)(_thh);                                            \
           _thh = _thh->hh_next;                                             \
        }                                                                    \
        _count += _bkt_count;                                                \
        if (tbl.buckets[_bkt_i].count !=  _bkt_count) {          \
           HASH_OOPS("invalid bucket count %d, actual %d\n",                  \
            tbl.buckets[_bkt_i].count, _bkt_count);              \
        }                                                                    \
    }                                                                        \
    if (_count != tbl.num_items) {                               \
        HASH_OOPS("invalid hh item count %d, actual %d\n",                    \
            tbl.num_items, _count );                             \
    }                                                                        \
    if (head) {                                                                  \
        /* traverse hh in app order; check next/prev integrity, count */         \
        _count = 0;                                                              \
        _prev = NULL;                                                            \
        _thh =  &(head)->hh;                                                     \
        while (_thh) {                                                           \
           _count++;                                                             \
           if (_prev !=(char*)(_thh->prev)) {                                    \
              HASH_OOPS("invalid prev %p, actual %p\n",                          \
                    _thh->prev, _prev );                                         \
           }                                                                     \
           _prev = (char*)ELMT_FROM_HH(&tbl, _thh);                    \
           _thh = ( _thh->next ?  (UT_hash_handle*)((char*)(_thh->next) +        \
                                  tbl.hho) : NULL );                 \
        }                                                                        \
        if (_count != tbl.num_items) {                               \
            HASH_OOPS("invalid app item count %d, actual %d\n",                   \
                tbl.num_items, _count );                             \
        }                                                                        \
    }                                                                            \
    else {                                                                       \
      if (tbl.num_items != 0) {                                                \
        HASH_OOPS("tbl.num_items=%d should be 0 since head is null\n", tbl.num_items);            \
      }                                                                          \
    }                                                                            \
} while (0)
#else
#define HASH_FSCK2(hh,head,tbl)
#endif

#define HASH_FSCK(hh, hash)                                                           \
  HASH_FSCK2(hh, (hash)->head, (hash)->tbl)

/* When compiled with -DHASH_EMIT_KEYS, length-prefixed keys are emitted to
 * the descriptor to which this macro is defined for tuning the hash function.
 * The app can #include <unistd.h> to get the prototype for write(2). */
#ifdef HASH_EMIT_KEYS
#define HASH_EMIT_KEY(hh,head,keyptr,fieldlen)                                   \
do {                                                                             \
    unsigned _klen = fieldlen;                                                   \
    write(HASH_EMIT_KEYS, &_klen, sizeof(_klen));                                \
    write(HASH_EMIT_KEYS, keyptr, fieldlen);                                     \
} while (0)
#else 
#define HASH_EMIT_KEY(hh,head,keyptr,fieldlen)
#endif

/* default to Jenkin's hash unless overridden e.g. DHASH_FUNCTION=HASH_SAX */
#ifdef HASH_FUNCTION
#define HASH_FCN HASH_FUNCTION
#else
#define HASH_FCN HASH_JEN
#endif

/* The Bernstein hash function, used in Perl prior to v5.6 */
#define HASH_BER(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _hb_keylen=keylen;                                                    \
  char *_hb_key=(char*)(key);                                                    \
  (hashv) = 0;                                                                   \
  while (_hb_keylen--)  { (hashv) = ((hashv) * 33) + *_hb_key++; }               \
  bkt = (hashv) & (num_bkts-1);                                                  \
} while (0)


/* SAX/FNV/OAT/JEN hash functions are macro variants of those listed at
 * http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx */
#define HASH_SAX(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _sx_i;                                                                \
  char *_hs_key=(char*)(key);                                                    \
  hashv = 0;                                                                     \
  for(_sx_i=0; _sx_i < keylen; _sx_i++)                                          \
      hashv ^= (hashv << 5) + (hashv >> 2) + _hs_key[_sx_i];                     \
  bkt = hashv & (num_bkts-1);                                                    \
} while (0)

#define HASH_FNV(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _fn_i;                                                                \
  char *_hf_key=(char*)(key);                                                    \
  hashv = 2166136261UL;                                                          \
  for(_fn_i=0; _fn_i < keylen; _fn_i++)                                          \
      hashv = (hashv * 16777619) ^ _hf_key[_fn_i];                               \
  bkt = hashv & (num_bkts-1);                                                    \
} while(0)

#define HASH_OAT(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _ho_i;                                                                \
  char *_ho_key=(char*)(key);                                                    \
  hashv = 0;                                                                     \
  for(_ho_i=0; _ho_i < keylen; _ho_i++) {                                        \
      hashv += _ho_key[_ho_i];                                                   \
      hashv += (hashv << 10);                                                    \
      hashv ^= (hashv >> 6);                                                     \
  }                                                                              \
  hashv += (hashv << 3);                                                         \
  hashv ^= (hashv >> 11);                                                        \
  hashv += (hashv << 15);                                                        \
  bkt = hashv & (num_bkts-1);                                                    \
} while(0)

#define HASH_JEN_MIX(a,b,c)                                                      \
do {                                                                             \
  a -= b; a -= c; a ^= ( c >> 13 );                                              \
  b -= c; b -= a; b ^= ( a << 8 );                                               \
  c -= a; c -= b; c ^= ( b >> 13 );                                              \
  a -= b; a -= c; a ^= ( c >> 12 );                                              \
  b -= c; b -= a; b ^= ( a << 16 );                                              \
  c -= a; c -= b; c ^= ( b >> 5 );                                               \
  a -= b; a -= c; a ^= ( c >> 3 );                                               \
  b -= c; b -= a; b ^= ( a << 10 );                                              \
  c -= a; c -= b; c ^= ( b >> 15 );                                              \
} while (0)

#define HASH_JEN(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _hj_i,_hj_j,_hj_k;                                                    \
  unsigned char *_hj_key=(unsigned char*)(key);                                  \
  hashv = 0xfeedbeef;                                                            \
  _hj_i = _hj_j = 0x9e3779b9;                                                    \
  _hj_k = (unsigned)keylen;                                                      \
  while (_hj_k >= 12) {                                                          \
    _hj_i +=    (_hj_key[0] + ( (unsigned)_hj_key[1] << 8 )                      \
        + ( (unsigned)_hj_key[2] << 16 )                                         \
        + ( (unsigned)_hj_key[3] << 24 ) );                                      \
    _hj_j +=    (_hj_key[4] + ( (unsigned)_hj_key[5] << 8 )                      \
        + ( (unsigned)_hj_key[6] << 16 )                                         \
        + ( (unsigned)_hj_key[7] << 24 ) );                                      \
    hashv += (_hj_key[8] + ( (unsigned)_hj_key[9] << 8 )                         \
        + ( (unsigned)_hj_key[10] << 16 )                                        \
        + ( (unsigned)_hj_key[11] << 24 ) );                                     \
                                                                                 \
     HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                          \
                                                                                 \
     _hj_key += 12;                                                              \
     _hj_k -= 12;                                                                \
  }                                                                              \
  hashv += keylen;                                                               \
  switch ( _hj_k ) {                                                             \
     case 11: hashv += ( (unsigned)_hj_key[10] << 24 );                          \
     case 10: hashv += ( (unsigned)_hj_key[9] << 16 );                           \
     case 9:  hashv += ( (unsigned)_hj_key[8] << 8 );                            \
     case 8:  _hj_j += ( (unsigned)_hj_key[7] << 24 );                           \
     case 7:  _hj_j += ( (unsigned)_hj_key[6] << 16 );                           \
     case 6:  _hj_j += ( (unsigned)_hj_key[5] << 8 );                            \
     case 5:  _hj_j += _hj_key[4];                                               \
     case 4:  _hj_i += ( (unsigned)_hj_key[3] << 24 );                           \
     case 3:  _hj_i += ( (unsigned)_hj_key[2] << 16 );                           \
     case 2:  _hj_i += ( (unsigned)_hj_key[1] << 8 );                            \
     case 1:  _hj_i += _hj_key[0];                                               \
  }                                                                              \
  HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                             \
  bkt = hashv & (num_bkts-1);                                                    \
} while(0)

/* The Paul Hsieh hash function */
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__)             \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)             \
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif
#define HASH_SFH(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned char *_sfh_key=(unsigned char*)(key);                                 \
  uint32_t _sfh_tmp, _sfh_len = keylen;                                          \
                                                                                 \
  int _sfh_rem = _sfh_len & 3;                                                   \
  _sfh_len >>= 2;                                                                \
  hashv = 0xcafebabe;                                                            \
                                                                                 \
  /* Main loop */                                                                \
  for (;_sfh_len > 0; _sfh_len--) {                                              \
    hashv    += get16bits (_sfh_key);                                            \
    _sfh_tmp       = (uint32_t)(get16bits (_sfh_key+2)) << 11  ^ hashv;          \
    hashv     = (hashv << 16) ^ _sfh_tmp;                                        \
    _sfh_key += 2*sizeof (uint16_t);                                             \
    hashv    += hashv >> 11;                                                     \
  }                                                                              \
                                                                                 \
  /* Handle end cases */                                                         \
  switch (_sfh_rem) {                                                            \
    case 3: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 16;                                                \
            hashv ^= (uint32_t)(_sfh_key[sizeof (uint16_t)] << 18);              \
            hashv += hashv >> 11;                                                \
            break;                                                               \
    case 2: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 11;                                                \
            hashv += hashv >> 17;                                                \
            break;                                                               \
    case 1: hashv += *_sfh_key;                                                  \
            hashv ^= hashv << 10;                                                \
            hashv += hashv >> 1;                                                 \
  }                                                                              \
                                                                                 \
    /* Force "avalanching" of final 127 bits */                                  \
    hashv ^= hashv << 3;                                                         \
    hashv += hashv >> 5;                                                         \
    hashv ^= hashv << 4;                                                         \
    hashv += hashv >> 17;                                                        \
    hashv ^= hashv << 25;                                                        \
    hashv += hashv >> 6;                                                         \
    bkt = hashv & (num_bkts-1);                                                  \
} while(0) 

#ifdef HASH_USING_NO_STRICT_ALIASING
/* The MurmurHash exploits some CPU's (x86,x86_64) tolerance for unaligned reads.
 * For other types of CPU's (e.g. Sparc) an unaligned read causes a bus error.
 * MurmurHash uses the faster approach only on CPU's where we know it's safe.
 *
 * Note the preprocessor built-in defines can be emitted using:
 *
 *   gcc -m64 -dM -E - < /dev/null                  (on gcc)
 *   cc -## a.c (where a.c is a simple test file)   (Sun Studio)
 */
#if (defined(__i386__) || defined(__x86_64__)  || defined(_M_IX86))
#define MUR_GETBLOCK(p,i) p[i]
#else /* non intel */
#define MUR_PLUS0_ALIGNED(p) (((unsigned long)p & 0x3) == 0)
#define MUR_PLUS1_ALIGNED(p) (((unsigned long)p & 0x3) == 1)
#define MUR_PLUS2_ALIGNED(p) (((unsigned long)p & 0x3) == 2)
#define MUR_PLUS3_ALIGNED(p) (((unsigned long)p & 0x3) == 3)
#define WP(p) ((uint32_t*)((unsigned long)(p) & ~3UL))
#if (defined(__BIG_ENDIAN__) || defined(SPARC) || defined(__ppc__) || defined(__ppc64__))
#define MUR_THREE_ONE(p) ((((*WP(p))&0x00ffffff) << 8) | (((*(WP(p)+1))&0xff000000) >> 24))
#define MUR_TWO_TWO(p)   ((((*WP(p))&0x0000ffff) <<16) | (((*(WP(p)+1))&0xffff0000) >> 16))
#define MUR_ONE_THREE(p) ((((*WP(p))&0x000000ff) <<24) | (((*(WP(p)+1))&0xffffff00) >>  8))
#else /* assume little endian non-intel */
#define MUR_THREE_ONE(p) ((((*WP(p))&0xffffff00) >> 8) | (((*(WP(p)+1))&0x000000ff) << 24))
#define MUR_TWO_TWO(p)   ((((*WP(p))&0xffff0000) >>16) | (((*(WP(p)+1))&0x0000ffff) << 16))
#define MUR_ONE_THREE(p) ((((*WP(p))&0xff000000) >>24) | (((*(WP(p)+1))&0x00ffffff) <<  8))
#endif
#define MUR_GETBLOCK(p,i) (MUR_PLUS0_ALIGNED(p) ? ((p)[i]) :           \
                            (MUR_PLUS1_ALIGNED(p) ? MUR_THREE_ONE(p) : \
                             (MUR_PLUS2_ALIGNED(p) ? MUR_TWO_TWO(p) :  \
                                                      MUR_ONE_THREE(p))))
#endif
#define MUR_ROTL32(x,r) (((x) << (r)) | ((x) >> (32 - (r))))
#define MUR_FMIX(_h) \
do {                 \
  _h ^= _h >> 16;    \
  _h *= 0x85ebca6b;  \
  _h ^= _h >> 13;    \
  _h *= 0xc2b2ae35l; \
  _h ^= _h >> 16;    \
} while(0)

#define HASH_MUR(key,keylen,num_bkts,hashv,bkt)                        \
do {                                                                   \
  const uint8_t *_mur_data = (const uint8_t*)(key);                    \
  const int _mur_nblocks = (keylen) / 4;                               \
  uint32_t _mur_h1 = 0xf88D5353;                                       \
  uint32_t _mur_c1 = 0xcc9e2d51;                                       \
  uint32_t _mur_c2 = 0x1b873593;                                       \
  uint32_t _mur_k1 = 0;                                                \
  const uint8_t *_mur_tail;                                            \
  const uint32_t *_mur_blocks = (const uint32_t*)(_mur_data+_mur_nblocks*4); \
  int _mur_i;                                                          \
  for(_mur_i = -_mur_nblocks; _mur_i; _mur_i++) {                      \
    _mur_k1 = MUR_GETBLOCK(_mur_blocks,_mur_i);                        \
    _mur_k1 *= _mur_c1;                                                \
    _mur_k1 = MUR_ROTL32(_mur_k1,15);                                  \
    _mur_k1 *= _mur_c2;                                                \
                                                                       \
    _mur_h1 ^= _mur_k1;                                                \
    _mur_h1 = MUR_ROTL32(_mur_h1,13);                                  \
    _mur_h1 = _mur_h1*5+0xe6546b64;                                    \
  }                                                                    \
  _mur_tail = (const uint8_t*)(_mur_data + _mur_nblocks*4);            \
  _mur_k1=0;                                                           \
  switch((keylen) & 3) {                                               \
    case 3: _mur_k1 ^= _mur_tail[2] << 16;                             \
    case 2: _mur_k1 ^= _mur_tail[1] << 8;                              \
    case 1: _mur_k1 ^= _mur_tail[0];                                   \
    _mur_k1 *= _mur_c1;                                                \
    _mur_k1 = MUR_ROTL32(_mur_k1,15);                                  \
    _mur_k1 *= _mur_c2;                                                \
    _mur_h1 ^= _mur_k1;                                                \
  }                                                                    \
  _mur_h1 ^= (keylen);                                                 \
  MUR_FMIX(_mur_h1);                                                   \
  hashv = _mur_h1;                                                     \
  bkt = hashv & (num_bkts-1);                                          \
} while(0)
#endif  /* HASH_USING_NO_STRICT_ALIASING */

//same as memcmp, but do not prefetch memory, so we are sure we do not read too much byte from source
static inline int safe_memcmp(const void* s1, const void* s2,size_t n)
{
    const unsigned char *p1 = s1, *p2 = s2;
    while(n--)
        if( *p1 != *p2 )
            return *p1 - *p2;
        else
            p1++,p2++;
    return 0;
}


/* key comparison function; return 0 if keys equal */
#ifdef HASH_COMPARE
#define HASH_KEYCMP HASH_COMPARE
#else
#if GCC_SANITIZE
#define HASH_KEYCMP(a,b,len) safe_memcmp(a,b,len)
#else
#define HASH_KEYCMP(a,b,len) memcmp(a,b,len)
#endif
#endif

/* iterate over items in a known bucket to find desired item */
#define HASH_FIND_IN_BKT(tbl,head,keyptr,key_fieldname,keylen_in,out)                       \
do {                                                                             \
 if (head.hh_head) DECLTYPE_ASSIGN(out,ELMT_FROM_HH(tbl,head.hh_head));          \
 else out=NULL;                                                                  \
 while (out) {                                                                   \
    if ((HASH_KEYCMP(&((out)->key_fieldname),keyptr,keylen_in)) == 0) break;             \
    if ((out)->hh.hh_next) DECLTYPE_ASSIGN(out,ELMT_FROM_HH(tbl,(out)->hh.hh_next)); \
    else out = NULL;                                                             \
 }                                                                               \
} while(0)

/* add an item to a bucket  */
#define HASH_ADD_TO_BKT(head,addhh)                                              \
do {                                                                             \
 head.count++;                                                                   \
 (addhh)->hh_next = head.hh_head;                                                \
 (addhh)->hh_prev = NULL;                                                        \
 if (head.hh_head) { (head).hh_head->hh_prev = (addhh); }                        \
 (head).hh_head=addhh;                                                           \
} while(0)

/* remove an item from a given bucket */
#define HASH_DEL_IN_BKT(hh,head,hh_del)                                          \
    (head).count--;                                                              \
    if ((head).hh_head == hh_del) {                                              \
      (head).hh_head = hh_del->hh_next;                                          \
    }                                                                            \
    if (hh_del->hh_prev) {                                                       \
        hh_del->hh_prev->hh_next = hh_del->hh_next;                              \
    }                                                                            \
    if (hh_del->hh_next) {                                                       \
        hh_del->hh_next->hh_prev = hh_del->hh_prev;                              \
    }

/* This is an adaptation of Simon Tatham's O(n log(n)) mergesort */
/* Note that HASH_SORT assumes the hash handle name to be hh.
 * HASH_SRT was added to allow the hash handle name to be passed in. */
#define HASH_SORT(head,cmpfcn) HASH_SRT(hh,head,cmpfcn)
#define HASH_SRT(hh,head,cmpfcn)                                                 \
do {                                                                             \
  unsigned _hs_i;                                                                \
  unsigned _hs_looping,_hs_nmerges,_hs_insize,_hs_psize,_hs_qsize;               \
  struct UT_hash_handle *_hs_p, *_hs_q, *_hs_e, *_hs_list, *_hs_tail;            \
  if (head) {                                                                    \
      _hs_insize = 1;                                                            \
      _hs_looping = 1;                                                           \
      _hs_list = &((head)->hh);                                                  \
      while (_hs_looping) {                                                      \
          _hs_p = _hs_list;                                                      \
          _hs_list = NULL;                                                       \
          _hs_tail = NULL;                                                       \
          _hs_nmerges = 0;                                                       \
          while (_hs_p) {                                                        \
              _hs_nmerges++;                                                     \
              _hs_q = _hs_p;                                                     \
              _hs_psize = 0;                                                     \
              for ( _hs_i = 0; _hs_i  < _hs_insize; _hs_i++ ) {                  \
                  _hs_psize++;                                                   \
                  _hs_q = (UT_hash_handle*)((_hs_q->next) ?                      \
                          ((void*)((char*)(_hs_q->next) +                        \
                          (head)->hh.tbl->hho)) : NULL);                         \
                  if (! (_hs_q) ) break;                                         \
              }                                                                  \
              _hs_qsize = _hs_insize;                                            \
              while ((_hs_psize > 0) || ((_hs_qsize > 0) && _hs_q )) {           \
                  if (_hs_psize == 0) {                                          \
                      _hs_e = _hs_q;                                             \
                      _hs_q = (UT_hash_handle*)((_hs_q->next) ?                  \
                              ((void*)((char*)(_hs_q->next) +                    \
                              (head)->hh.tbl->hho)) : NULL);                     \
                      _hs_qsize--;                                               \
                  } else if ( (_hs_qsize == 0) || !(_hs_q) ) {                   \
                      _hs_e = _hs_p;                                             \
                      _hs_p = (UT_hash_handle*)((_hs_p->next) ?                  \
                              ((void*)((char*)(_hs_p->next) +                    \
                              (head)->hh.tbl->hho)) : NULL);                     \
                      _hs_psize--;                                               \
                  } else if ((                                                   \
                      cmpfcn(DECLTYPE(head)(ELMT_FROM_HH((head)->hh.tbl,_hs_p)), \
                             DECLTYPE(head)(ELMT_FROM_HH((head)->hh.tbl,_hs_q))) \
                             ) <= 0) {                                           \
                      _hs_e = _hs_p;                                             \
                      _hs_p = (UT_hash_handle*)((_hs_p->next) ?                  \
                              ((void*)((char*)(_hs_p->next) +                    \
                              (head)->hh.tbl->hho)) : NULL);                     \
                      _hs_psize--;                                               \
                  } else {                                                       \
                      _hs_e = _hs_q;                                             \
                      _hs_q = (UT_hash_handle*)((_hs_q->next) ?                  \
                              ((void*)((char*)(_hs_q->next) +                    \
                              (head)->hh.tbl->hho)) : NULL);                     \
                      _hs_qsize--;                                               \
                  }                                                              \
                  if ( _hs_tail ) {                                              \
                      _hs_tail->next = ((_hs_e) ?                                \
                            ELMT_FROM_HH((head)->hh.tbl,_hs_e) : NULL);          \
                  } else {                                                       \
                      _hs_list = _hs_e;                                          \
                  }                                                              \
                  _hs_e->prev = ((_hs_tail) ?                                    \
                     ELMT_FROM_HH((head)->hh.tbl,_hs_tail) : NULL);              \
                  _hs_tail = _hs_e;                                              \
              }                                                                  \
              _hs_p = _hs_q;                                                     \
          }                                                                      \
          _hs_tail->next = NULL;                                                 \
          if ( _hs_nmerges <= 1 ) {                                              \
              _hs_looping=0;                                                     \
              (head)->hh.tbl->tail = _hs_tail;                                   \
              DECLTYPE_ASSIGN(head,ELMT_FROM_HH((head)->hh.tbl, _hs_list));      \
          }                                                                      \
          _hs_insize *= 2;                                                       \
      }                                                                          \
 }                                                                               \
} while (0)

#define HASH_OVERHEAD(hh,head)                                                   \
 (size_t)((((head)->hh.tbl->num_items   * sizeof(UT_hash_handle))   +            \
           ((head)->hh.tbl->num_buckets * sizeof(UT_hash_bucket))   +            \
            (sizeof(UT_hash_table))                                 +            \
            (HASH_BLOOM_BYTELEN)))

#ifdef NO_DECLTYPE
#define HASH_ITER(hh,head,el,tmp)                                                \
for((el)=(head), (*(char**)(&(tmp)))=(char*)((head)?(head)->hh.next:NULL);       \
  el; (el)=(tmp),(*(char**)(&(tmp)))=(char*)((tmp)?(tmp)->hh.next:NULL))
#else
#define HASH_ITER(hh,head,el,tmp)                                                \
for((el)=(head),(tmp)=DECLTYPE(el)((head)?(head)->hh.next:NULL);                 \
  el; (el)=(tmp),(tmp)=DECLTYPE(el)((tmp)?(tmp)->hh.next:NULL))
#endif

/* obtain a count of items in the hash */
#define HASH_COUNT(hash) HASH_CNT(hh,hash)
#define HASH_CNT(hh,hash) ((hash)?((hash)->tbl.num_items):0)

#define HASH_CHAIN_COUNT(hash, idx) ((hash)->tbl.stat_bucket_##idx)
#define HASH_USAGE(hash) (hash)->tbl.num_buckets>0 ? ((double)(hash)->tbl.num_items / (double)(hash)->tbl.num_buckets) : 0.0
#define HASH_NUM_BUCKETS(hash) (hash)->tbl.num_buckets

#define HASH_CLEAR(hash)                        \
do {                                            \
  (hash)->tbl.num_items = 0;                    \
} while(0)


#define HASH_COMPUTE_STATS2(hh,head,tbl)                                          \
do {                                                                              \
    unsigned _bkt_i;                                                              \
    unsigned _bkt_count;                                                          \
    struct UT_hash_handle *_thh;                                                  \
    tbl.stat_bucket_1 = 0;                                                        \
    tbl.stat_bucket_2 = 0;                                                        \
    tbl.stat_bucket_4 = 0;                                                        \
    tbl.stat_bucket_8 = 0;                                                        \
    tbl.stat_bucket_16 = 0;                                                       \
    for( _bkt_i = 0; _bkt_i < tbl.num_buckets; _bkt_i++) {                        \
        _bkt_count = 0;                                                           \
        _thh = tbl.buckets[_bkt_i].hh_head;                                       \
        while (_thh) {                                                            \
           _bkt_count++;                                                          \
           _thh = _thh->hh_next;                                                  \
        }                                                                         \
        tbl.stat_bucket_1 += _bkt_count >= 1 ? 1 : 0;                             \
        tbl.stat_bucket_2 += _bkt_count >= 2 ? 1 : 0;                             \
        tbl.stat_bucket_4 += _bkt_count >= 4 ? 1 : 0;                             \
        tbl.stat_bucket_8 += _bkt_count >= 8 ? 1 : 0;                             \
        tbl.stat_bucket_16 += _bkt_count >= 16 ? 1 : 0;                           \
    }                                                                             \
} while (0)
#define HASH_COMPUTE_STATS(hash)      \
HASH_COMPUTE_STATS2(hh, (hash)->head, (hash)->tbl)


#ifndef UTHASH_H
#define UTHASH_H

/* random signature used only to find hash tables in external analysis */
#define HASH_SIGNATURE 0xa0111fe1
#define HASH_BLOOM_SIGNATURE 0xb12220f2

//split types in another file, so user can include only "uthash_types.h" in its .h files
//and include "uthash.h" file in its .c and use a custom hash func declared in the .c only
#include "uthash_ovh_types.h"

#endif /* UTHASH_H */
