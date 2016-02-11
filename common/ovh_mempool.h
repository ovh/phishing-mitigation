#ifndef __OVH_MEMPOOL__
#define __OVH_MEMPOOL__

#include <stdint.h>
#include <stddef.h> // For ptrdiff_t
#include <memory.h> // memset

#include "ovh_tmc.h"
#include "ovh_log.h"

/*
 * This file provides macros to allocate memory pools of fixed-size items
 * To use these macros, your struct should contain the field :
 *
 * struct my_struct *mp_next;
 *
 * so the memory pool can use it to manage its linked-list of free items
 *
 * BEWARE that this memory pool is simplified to the extreme for efficiency,
 * and thus doesn't perform any sort of consistency check in any way.
 * It is the user's responsibility to ensure a proper usage.
 *
 * Memory is allocated in chunks of 32MB, to accomodate for memory fragmentation.
 */

#ifndef OVH_MEMPOOL_DEBUG
#define OVH_MEMPOOL_DEBUG 0
#endif // OVH_MEMPOOL_DEBUG

#define __OVH_MEMPOOL_MEMORY_CHUNKS 32 * 1024 * 1024

typedef struct
{
  void *data;
  uint32_t size;
} ovh_mempool_array;

typedef struct
{
  tmc_spin_queued_mutex_t lock;
  void *free;
  uint32_t item_size;
  uint32_t nb_items;
  uint32_t nb_items_free;
  ovh_mempool_array* arrays;
  uint32_t arrays_count;
#if OVH_MEMPOOL_DEBUG
  ptrdiff_t offset_to_mp_next;
#endif
} ovh_mempool;

/*******************************************************************************************
 * DEBUG MACROS
 *******************************************************************************************/
#if OVH_MEMPOOL_DEBUG

#define __OVH_MEMPOOL_DEBUG_INIT(pool, struct_name) \
do { \
  (pool).offset_to_mp_next = offsetof(struct_name, mp_next); \
} while(0)


// TODO Detect double free : items present more than once in the linked-list
#define __OVH_MEMPOOL_CHECK(pool, __unused)                           \
  void * __ovh_mp_tmp = (pool).free; \
  uint32_t __ovh_mp_cnt = 0; \
  while (__ovh_mp_tmp) { \
    __ovh_mp_cnt++; \
    if (__ovh_mp_cnt > (pool).nb_items_free) { \
      PRINT_ERR("More items in linked-list than in (pool).nb_items_free (%u) !\n", (pool).nb_items_free); \
      break; \
    } \
    __ovh_mp_tmp = *((char **)(__ovh_mp_tmp + ((pool).offset_to_mp_next))); \
  } \
  if (__ovh_mp_cnt != (pool).nb_items_free) PRINT_ERR("(pool).nb_items_free is %u but I found %u items in the linked-list\n", (pool).nb_items_free, __ovh_mp_cnt); \
do {                                                              \
} while(0)
#else
// Dummies
#define __OVH_MEMPOOL_DEBUG_INIT(pool, struct_name)
#define __OVH_MEMPOOL_CHECK(pool, item)
#endif //OVH_MEMPOOL_DEBUG
/*******************************************************************************************/

/*
 * OVH_MEMPOOL_CREATE
 *
 * Allocate a memory pool.
 * - pool : an ovh_mempool
 * - struct_name : the name of the struct to use as base items
 * - __nb_items : the number of items to allocate
 * use allocator only for items allocation, still use calloc for small pool.arrays
 */
#define OVH_MEMPOOL_CREATE_WITH(pool, struct_name, __nb_items, allocator, ...)                  \
do {                                                                                            \
  memset(&(pool), 0, sizeof(ovh_mempool));                                                      \
  (pool).item_size = sizeof(struct_name);                                                       \
  (pool).nb_items = __nb_items;                                                                 \
  (pool).nb_items_free = __nb_items;                                                            \
  uint32_t __items_per_array = __OVH_MEMPOOL_MEMORY_CHUNKS / sizeof(struct_name);               \
  (pool).arrays_count = __nb_items / __items_per_array;                                         \
  if (__nb_items % __items_per_array)                                                           \
    (pool).arrays_count++;                                                                      \
  (pool).arrays = OVH_CALLOC((pool).arrays_count, sizeof(ovh_mempool_array));                   \
  if ((pool).arrays) {                                                                          \
    for (int __i = 0; __i < (pool).arrays_count; __i++) {                                       \
      uint32_t __nb_items_i = (__i == (pool).arrays_count - 1 && __items_per_array*(pool).arrays_count != __nb_items) ? \
                                  __nb_items % __items_per_array :                              \
                                  __items_per_array;                                            \
      (pool).arrays[__i].data = allocator (__nb_items_i, sizeof(struct_name), __VA_ARGS__);     \
      (pool).arrays[__i].size = __nb_items_i * sizeof(struct_name);                             \
      (pool).free = (pool).arrays[__i].data;                                                    \
      if ((pool).free != NULL)                                                                  \
      {                                                                                         \
        for (int __j = 0; __j < __nb_items_i - 1; __j++)                                        \
        {                                                                                       \
          ((struct_name*) (pool).free + __j)->mp_next = ((struct_name*) (pool).free + __j + 1); \
        }                                                                                       \
        if (__i != 0) {                                                                         \
          /* Link the last of this array to the first of the previous one */                    \
          ((struct_name*) (pool).arrays[__i].data + __nb_items_i - 1)->mp_next =                     \
            ((struct_name*) (pool).arrays[__i-1].data);                                              \
        }                                                                                       \
      }                                                                                         \
      else break;                                                                               \
    }                                                                                           \
  }                                                                                             \
  __OVH_MEMPOOL_DEBUG_INIT(pool, struct_name);                                                  \
  __OVH_MEMPOOL_CHECK(pool, (pool).free);                                                       \
  tmc_spin_queued_mutex_init(&((pool).lock));                                                   \
} while (0)

#if OVH_MEMPOOL_HUGEPAGES
#define OVH_MEMPOOL_ALLOCATOR(__count, __size, __not_used__) OVH_AUTO_PAGED_ALLOCATOR(__count, __size, __not_used__)
#else
#define OVH_MEMPOOL_ALLOCATOR(__count, __size, __not_used__) OVH_CALLOC(__count, __size)
#endif

#define OVH_MEMPOOL_CREATE(pool, struct_name, __nb_items)                                       \
do {                                                                                            \
  OVH_MEMPOOL_CREATE_WITH(pool, struct_name, __nb_items, OVH_MEMPOOL_ALLOCATOR, __not_used);    \
}while(0)

static INLINE void* ovh_mempool_shared_alloc(size_t count, size_t size, tmc_alloc_t* allocator)
{
  size_t totalSize = count * size;
  void* res = tmc_alloc_map(allocator, totalSize);
  if (res == NULL)
    tmc_task_die("Failed to allocate from ovh_map_alloc(), %zu bytes", totalSize);

  memset(res, 0, totalSize); //touch it at least once
  return res;
}

#define OVH_MEMPOOL_CREATE_SHARED(pool, struct_name, __nb_items, tmc_alloc)                       \
do {                                                                                              \
  pool = ovh_mempool_shared_alloc(1, sizeof(ovh_mempool), tmc_alloc);                                                      \
  OVH_MEMPOOL_CREATE(*pool, struct_name, __nb_items);   \
}while(0)

/*
 * OVH_MEMPOOL_ALLOC
 *
 * Allocate an item from the pool.
 * 'out' will point to the new item, or be NULL if the pool is empty.
 */
#define OVH_MEMPOOL_ALLOC(pool, out)                                                            \
do {                                                                                            \
  tmc_spin_queued_mutex_lock(&((pool).lock));                                                   \
  out = (pool).free;                                                                            \
  if (out != NULL) {                                                                            \
    (pool).free = out->mp_next;                                                                 \
    (pool).nb_items_free--;                                                                     \
  }                                                                                             \
  else                                                                                          \
    (pool).free = NULL;                                                                         \
  __OVH_MEMPOOL_CHECK(pool, out);                                                               \
  tmc_spin_queued_mutex_unlock(&((pool).lock));                                                 \
} while (0)

#define OVH_MEMPOOL_ALLOC_ZEROED(pool, out)                                                     \
do {                                                                                            \
  OVH_MEMPOOL_ALLOC(pool, out);                                                                 \
  if(out != NULL) {                                                                             \
    memset(out, 0, sizeof(*out));                                                                  \
  }                                                                                             \
} while (0)

#define OVH_MEMPOOL_ALLOC_LL(pool, count, tmp, out)                                             \
do {                                                                                            \
  tmc_spin_queued_mutex_lock(&((pool).lock));                                                   \
  out = (pool).free;                                                                            \
  int left = count;                                                                             \
  if (out != NULL) {                                                                            \
    tmp = out;                                                                                  \
    while (tmp) {                                                                               \
      left--;                                                                                   \
      if (left == 0)                                                                            \
      {                                                                                         \
        (pool).free = tmp->mp_next;                                                             \
        tmp->mp_next = NULL;                                                                    \
        tmp = (pool).free;                                                                      \
        break;                                                                                  \
      }                                                                                         \
      tmp = tmp->mp_next;                                                                       \
    }                                                                                           \
    (pool).free = tmp;                                                                          \
  }                                                                                             \
  (pool).nb_items_free -= count - left;                                                         \
  __OVH_MEMPOOL_CHECK(pool, out);                                                               \
  tmc_spin_queued_mutex_unlock(&((pool).lock));                                                 \
} while (0)


/*
 * OVH_MEMPOOL_FREE
 *
 * Free an item to its pool.
 * Beware that no consistency check is made, which means the following will go undetected :
 * - freeing an item twice
 * - freeing an item to the wrong pool
 * - ...
 */
#define OVH_MEMPOOL_FREE(pool, item)                                                            \
do {                                                                                            \
  tmc_spin_queued_mutex_lock(&((pool).lock));                                                   \
  item->mp_next = (pool).free;                                                                  \
  (pool).free = item;                                                                           \
  (pool).nb_items_free++;                                                                       \
  __OVH_MEMPOOL_CHECK(pool, item);                                                              \
  tmc_spin_queued_mutex_unlock(&((pool).lock));                                                 \
} while (0)

/*
 * OVH_MEMPOOL_FREE_LL
 *
 * Free a linked list of items to its pool.
 * - 'first' should link all the way to 'last', otherwise it will break the ll of free items.
 * - size : the size of the linked list
 * No consistency check done !
 */
#define OVH_MEMPOOL_FREE_LL(pool, first, last, size)                                            \
do {                                                                                            \
  tmc_spin_queued_mutex_lock(&((pool).lock));                                                   \
  last->mp_next = (pool).free;                                                                  \
  (pool).free = first;                                                                          \
  (pool).nb_items_free += size;                                                                 \
  __OVH_MEMPOOL_CHECK(pool, first);                                                             \
  tmc_spin_queued_mutex_unlock(&((pool).lock));                                                 \
} while (0)

/*
 * OVH_MEMPOOL_DISCARD
 *
 * Free all the memory allocated back to the system.
 */
 //TODO fix OVH_FREE_MAP argument with correct allocated size
#define OVH_MEMPOOL_DISCARD(pool)                                                               \
do {                                                                                            \
  tmc_spin_queued_mutex_lock(&((pool).lock));                                                   \
  if ((pool).arrays) {                                                                          \
    for (int i = 0; i < (pool).arrays_count; i++) {                                             \
      if ((pool).arrays[i].data)                                                                \
        OVH_FREE_MAP((pool).arrays[i].data, (pool).arrays[i].size);                             \
    }                                                                                           \
    OVH_FREE_MAP((pool).arrays, sizeof(ovh_mempool_array));                                     \
  }                                                                                             \
  tmc_spin_queued_mutex_unlock(&((pool).lock));                                                 \
} while (0)


#define OVH_MEMPOOL_PRINT_USAGE(F, MP, TOTAL_MEMUSED, TOTAL_MEMALLOCATED, MP_USAGE)   \
do {                                                                        \
  if (MP != NULL) {                                                         \
    char __buf[32];                                                         \
    uint64_t __mem_used = OVH_MEMPOOL_STATS_USED(*MP);                      \
    TOTAL_MEMUSED += __mem_used;                                            \
    format_human(__mem_used, __buf);                                        \
    char __buf2[32];                                                        \
    uint64_t __mem_allocated = OVH_MEMPOOL_STATS_ALLOCATED(*MP);            \
    TOTAL_MEMALLOCATED += __mem_allocated;                                  \
    MP_USAGE = (100 * __mem_used) / __mem_allocated;                        \
    format_human(__mem_allocated, __buf2);                                  \
    uint32_t items_used = (*MP).nb_items - (*MP).nb_items_free;             \
    int char_count = fprintf(F, "MP " #MP "");                                    \
    FPRINTF_SPACE(F, 37 - char_count);                                   \
    fprintf(F, " | %6.3f%%  | %8u | %8u  | %s | %s\n", ((double)items_used / (double)(*MP).nb_items) * 100.0f, items_used, (*MP).nb_items, __buf, __buf2);\
  }                                                                         \
} while(0)

#define OVH_MEMPOOL_DISCARD_SHARED(pool)                                    \
do {                                                                        \
  OVH_MEMPOOL_DISCARD(*pool);                                               \
  OVH_FREE_MAP(pool, sizeof(ovh_mempool));                                  \
} while(0)

/*
 * Usage statistics
 */
#define OVH_MEMPOOL_STATS_ALLOCATED(pool) ((pool).nb_items * (pool).item_size)
#define OVH_MEMPOOL_STATS_USED(pool) (((pool).nb_items - (pool).nb_items_free) * (pool).item_size)
#define OVH_MEMPOOL_STATS_COUNT(pool) ((pool).nb_items - (pool).nb_items_free)
#define OVH_MEMPOOL_STATS_FREE(pool) ((pool).nb_items_free * (pool).item_size)

#endif // __OVH_MEMPOOL__
