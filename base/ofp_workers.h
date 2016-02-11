#ifndef __OFP_WORKERS_H__
#define __OFP_WORKERS_H__

#include <stdint.h>
#include <pthread.h>

// Number of workers (threads)
extern int work_size;

// Pointer to a barrier
// Shared by all worker threads to do synchronization
extern pthread_barrier_t* work_barrier;

// This will be set to 1 when worker threads have ended
extern int prgm_exit_requested;

#endif //__OFP_WORKERS_H__
