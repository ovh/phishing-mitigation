#ifndef __OVH_ALLOC_H__
#define __OVH_ALLOC_H__

#include <stdlib.h>
#include <memory.h>
#include <inttypes.h>

#if TMC
#include <tmc/alloc.h>
#include <tmc/cpus.h>
#include <tmc/task.h>
#endif

#include "ovh_log.h"

#define OVH_PAGESIZE_64K (64 * 1024)
#define OVH_PAGESIZE_1M (1 *1024 * 1024)
#define OVH_PAGESIZE_16M (16 *1024 * 1024)

static inline void ovh_auto_pagesize_from_size(tmc_alloc_t* allocator, size_t size)
{
  if (size > OVH_PAGESIZE_64K)
  {
    if (size > OVH_PAGESIZE_1M)
    {
      tmc_alloc_set_pagesize(allocator, OVH_PAGESIZE_16M);
      return;
    }
    else
    {
      tmc_alloc_set_pagesize(allocator, OVH_PAGESIZE_1M);
      return;
    }
  }
  //default value
  tmc_alloc_set_pagesize(allocator, 0);
}

/*
* allocate buffer hommed on cpu 'rank' if given
* try to choose best page size from the given size
* Rank < 0 : default homed behaviour
* dataplaneCpus == NULL : default homed behaviour
*/
static inline void* ovh_map_alloc(size_t totalSize, cpu_set_t* dataplaneCpus, int rank)
{
  tmc_alloc_t allocator = TMC_ALLOC_INIT; //default allocator
  ovh_auto_pagesize_from_size(&allocator, totalSize);

  if(rank>=0 && dataplaneCpus!=NULL)
  {
    tmc_alloc_set_home(&allocator, tmc_cpus_find_nth_cpu(dataplaneCpus, rank));
  }
  else
  {
    tmc_alloc_set_home(&allocator, TMC_ALLOC_HOME_HASH);
  }

  void* res = tmc_alloc_map(&allocator, totalSize);
  if (res == NULL)
    tmc_task_die("Failed to allocate from ovh_map_alloc(), %zu bytes", totalSize);

  memset(res, 0, totalSize); //touch it at least once
  return res;
}

static inline void *ovh_map_malloc(size_t size)
{
  void* res = ovh_map_alloc(size, NULL, 0);
  if (res == NULL)
    tmc_task_die("Failed to allocate from ovh_map_malloc(), %zu bytes", size);

  memset(res, 0, size); //touch it at least once
  return res;
}

static inline void *ovh_map_calloc(size_t count, size_t size)
{
  size_t totalSize = count*size;
  void* res = ovh_map_alloc(totalSize, NULL, 0);
  if (res == NULL)
    tmc_task_die("Failed to allocate from ovh_map_calloc(), %zu bytes", totalSize);

  memset(res, 0, totalSize); //To be sure memory is zeroed and touch it at least once
  return res;
}

static inline void ovh_free_map(void* ptr, size_t size)
{
  tmc_alloc_unmap(ptr, size);
}


#if OVH_LOG_ALLOC
static inline void* logged_ovh_map_alloc(size_t size, cpu_set_t* dataplaneCpus, int rank, const char* func, const char* file, int line)
{
  debug_printf("ALLOC", file, func, line, "%zu ovh_map_alloc(%zu)\n", size, size);
  return ovh_map_alloc(size, dataplaneCpus, rank);
}

static inline void *logged_ovh_map_malloc(size_t size, const char* func, const char* file, int line)
{
  debug_printf("ALLOC", file, func, line, "%d ovh_map_malloc(%d)\n", size, size);
  return ovh_map_malloc(size);
}

static inline void *logged_ovh_map_calloc(size_t count, size_t size, const char* func, const char* file, int line)
{
  debug_printf("ALLOC", file, func, line, "%d ovh_map_calloc(%d,%d)\n", count * size, count, size);
  return ovh_map_calloc(count, size);
}

static inline void logged_ovh_free_map(void* ptr, size_t size, const char* func, const char* file, int line)
{
  debug_printf("FREE", file, func, line, "ovh_free_map(%p, %u)\n", ptr, size);
  ovh_free_map(ptr, size);
}


static inline void *logged_ovh_malloc(size_t size, const char* func, const char* file, int line)
{
  debug_printf("ALLOC", file, func, line, "%d malloc(%d)\n", size, size);
  return malloc(size);
}

static inline void *logged_ovh_calloc(size_t count, size_t size, const char* func, const char* file, int line)
{
  debug_printf("ALLOC", file, func, line, "%d calloc(%d,%d)\n", count * size, count, size);
  return calloc(count, size);
}

static inline void logged_ovh_free(void* ptr, const char* func, const char* file, int line)
{
  debug_printf("FREE", file, func, line, "free(%p)\n", ptr);
  free(ptr);
}

#endif //OVH_LOG_ALLOC

#if OVH_LOG_ALLOC
#define OVH_MAP_ALLOC(__size, __cpu_set, __rank) logged_ovh_map_alloc(__size, __cpu_set, __rank, __func__, __FILE__, __LINE__)
#define OVH_MAP_MALLOC(__size) logged_ovh_map_malloc(__size, __func__, __FILE__, __LINE__)
#define OVH_MAP_CALLOC(__count, __size) logged_ovh_map_calloc(__count, __size, __func__, __FILE__, __LINE__)
#define OVH_FREE_MAP(__ptr, __size) do{ logged_ovh_free_map(__ptr, __size, __func__, __FILE__, __LINE__); __ptr = NULL; }while(0)

#define OVH_MALLOC(__size) logged_ovh_malloc(__size, __func__, __FILE__, __LINE__)
#define OVH_CALLOC(__count, __size) logged_ovh_calloc(__count, __size, __func__, __FILE__, __LINE__)
#define OVH_FREE(__ptr) do{ logged_ovh_free(__ptr, __func__, __FILE__, __LINE__); __ptr = NULL; }while(0)
#else //OVH_LOG_ALLOC
#define OVH_MAP_ALLOC(__size, __cpu_set, __rank) ovh_map_alloc(__size, __cpu_set, __rank)
#define OVH_MAP_MALLOC(__size) ovh_map_malloc(__size)
#define OVH_MAP_CALLOC(__count, __size) ovh_map_calloc(__count, __size)
#define OVH_FREE_MAP(__ptr, __size) do{ ovh_free_map(__ptr, __size); __ptr = NULL; }while(0)

#define OVH_MALLOC(__size) malloc(__size)
#define OVH_CALLOC(__count, __size) calloc(__count, __size)
#define OVH_FREE(__ptr) do{ free(__ptr); __ptr = NULL; }while(0)
#endif //!OVH_LOG_ALLOC

//TODO logged version

#if 0
#define malloc use_ovh_malloc_instead
#define calloc use_ovh_calloc_instead
#define realloc use_ovh_realloc_instead
#endif

#define OVH_HOMED_ALLOCATOR(__count, __size, __rank) OVH_MAP_ALLOC((__count) * (__size), &dataplane_cpus, __rank)
#define OVH_AUTO_PAGED_ALLOCATOR(__count, __size, __not_used) OVH_MAP_ALLOC((__count) * (__size), NULL, 0)


#endif //__OVH_ALLOC_H__
