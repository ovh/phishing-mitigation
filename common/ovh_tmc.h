#ifndef __OVH_TMC_H__
#define __OVH_TMC_H__

#include <stdint.h>
#include "ovh_defines.h"

#if TMC

#include <tmc/spin.h>
#include <tmc/task.h>
#include <tmc/alloc.h>
#include <tmc/cpus.h>

#define TMC_TASK_DIE(...) \
  do {\
    PRINT_ERR(__VA_ARGS__); \
    tmc_task_die(__VA_ARGS__);\
  } while(0)

#define FAIL(...) TMC_TASK_DIE(__VA_ARGS__)
#define PTHREAD_BARRIER_WAIT(ARG) pthread_barrier_wait(ARG)


#else //TMC


#include <pthread.h> //for threading , link with lpthread

typedef pthread_mutex_t tmc_spin_queued_mutex_t;
typedef pthread_mutex_t tmc_spin_mutex_t;


#if 1
#define tmc_spin_queued_mutex_init(ARG) pthread_mutex_init(ARG, NULL)
#define tmc_spin_queued_mutex_lock(ARG) pthread_mutex_lock(ARG)
#define tmc_spin_queued_mutex_unlock(ARG) pthread_mutex_unlock(ARG)
#else
#define tmc_spin_queued_mutex_init(ARG) UNUSED(ARG)
#define tmc_spin_queued_mutex_lock(ARG) UNUSED(ARG)
#define tmc_spin_queued_mutex_unlock(ARG) UNUSED(ARG)
#endif

//multi threading
void  tmc_spin_mutex_lock (tmc_spin_mutex_t *mutex);
#define tmc_spin_mutex_unlock(ARG) UNUSED(ARG)
#define PTHREAD_BARRIER_WAIT(ARG) UNUSED(ARG)

//aloc
typedef struct { int foo; } tmc_alloc_t;
#define TMC_ALLOC_INIT {0}
#define tmc_alloc_set_home(alloc, home) UNUSED(alloc)
#define tmc_alloc_map(alloc, size) malloc(size)
#define tmc_alloc_unmap(ptr, size) free(ptr)
#define tmc_alloc_set_pagesize(ARG1, ARG2) UNUSED(ARG1)

//cpu
//typedef cpu_set_t
#define tmc_cpus_get_online_cpus(cpu_set) 0
#define tmc_cpus_get_dataplane_cpus(cpu_set) 0
#define tmc_cpus_remove_cpus(ARG1, ARG2)
#define tmc_cpus_count(cpu_set) 16
#define tmc_cpus_find_nth_cpu(cpu_set, index) index
#define tmc_cpus_set_my_cpu(index) 0


#define FAIL(...) \
do {\
  PRINT_ERR(__VA_ARGS__); \
  exit(1); \
} while(0)

#define TMC_TASK_DIE(...) FAIL(__VA_ARGS__) //should use this
#define tmc_task_die(...) FAIL(__VA_ARGS__) //for legacy...


#endif //TMC


#endif //__OVH_TMC_H__
