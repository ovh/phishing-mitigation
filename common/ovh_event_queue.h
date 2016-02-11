#ifndef OVH_EVENT_QUEUE_H_
# define OVH_EVENT_QUEUE_H_

#include <pthread.h>
#include <stdlib.h>

#include "ovh_mempool.h"

#ifndef OVH_EVENT_QUEUE_DEBUG
#define OVH_EVENT_QUEUE_DEBUG 0
#endif // OVH_EVENT_QUEUE_DEBUG


/*
 * Event queue object
 * Should be used with tmc spin queued mutex only
 */
typedef struct
{
  uint32_t size; /* events count */
  void* first; /* The events */
  void* last; /* The last event */
  ovh_mempool* mempool;
  tmc_spin_queued_mutex_t mutex; /* lock */
} ovh_event_queue_t;

/*
 * Event queue object
 * Should be used with pthread mutex only
 * TODO: find a better way to do this
 */
typedef struct
{
  uint32_t size; /* max events count */
  void* first; /* The events */
  void* last; /* The last events */
  pthread_mutex_t mutex; /* lock */
  ovh_mempool* mempool;
} ovh_event_queue_pthread_t;


#if DEBUG
#define OVH_EVENT_QUEUE_OOPS(...) do { fprintf(stderr,__VA_ARGS__); exit(-1); } while (0)
#else
//in relase, just output error & try to continue ...
#define OVH_EVENT_QUEUE_OOPS(...) do { PRINT_ERR(__VA_ARGS__); } while (0)
#endif

#if OVH_EVENT_QUEUE_DEBUG

#define OVH_EVENT_QUEUE_LOCKED_CHECK(__locked_queue, entry_struct)  \
do {                                                                \
  uint32_t __count = 0;                                             \
  entry_struct* __cur = (__locked_queue)->first;                    \
  entry_struct* __last = __cur;                                     \
  while ( __cur != NULL) {                                          \
    __count++;                                                      \
    __last = __cur;                                                 \
    __cur = __cur->next;                                            \
  }                                                                 \
  if(__count != (__locked_queue)->size) OVH_EVENT_QUEUE_OOPS("invalid queue->size in %s : %d but expected %d\n", #__locked_queue, __count, (__locked_queue)->size);\
  if(__last != (__locked_queue)->last) OVH_EVENT_QUEUE_OOPS("invalid queue->last in %s\n", #__locked_queue); \
} while(0)

#define OVH_EVENT_QUEUE_CHECK(queue, entry_struct)                  \
do {                                                                \
  tmc_spin_queued_mutex_lock(&((queue)->mutex));                    \
  OVH_EVENT_QUEUE_LOCKED_CHECK(queue, entry_struct);                \
  tmc_spin_queued_mutex_unlock(&((queue)->mutex));                  \
}while(0)

#define OVH_EVENT_QUEUE_PTHREAD_CHECK(queue, entry_struct)          \
do {                                                                \
  pthread_mutex_lock(&((queue)->mutex));                            \
  OVH_EVENT_QUEUE_LOCKED_CHECK(queue, entry_struct);                \
  pthread_mutex_unlock(&((queue)->mutex));                          \
}while(0)

#else //OVH_EVENT_QUEUE_DEBUG

#define OVH_EVENT_QUEUE_LOCKED_CHECK(__locked_queue, entry_struct)
#define OVH_EVENT_QUEUE_CHECK(queue, entry_struct)
#define OVH_EVENT_QUEUE_PTHREAD_CHECK(queue, entry_struct)

#endif //OVH_EVENT_QUEUE_DEBUG

/*
 * Initialize the message queue
 * params:
 *  - queue: a pointer, already allocated to a ovh_event_queue_t
 *  - mem_size (size): the number of item that the queue can have
 *  - entry_struct: the struct used to store the datas
 *
 *  This use tmc_spin_queued_mutex_t
 */
#define OVH_EVENT_QUEUE_INIT_WITH(queue, mem_size, entry_struct, allocator, ...)          \
do {                                                                 \
  (queue)->size = 0;                                                 \
  (queue)->first = NULL;                                             \
  (queue)->last = NULL;                                              \
  (queue)->mempool = OVH_MAP_CALLOC(1, sizeof(ovh_mempool));       \
  if ((queue)->mempool == NULL)                                      \
    tmc_task_die("Failed to allocate event_queue mempool object\n"); \
  OVH_MEMPOOL_CREATE_WITH(*(queue)->mempool, entry_struct, mem_size, allocator, __VA_ARGS__);     \
  if ((queue)->mempool->free == NULL)                                \
    tmc_task_die("Failed to allocate event_queue mempool\n");        \
  tmc_spin_queued_mutex_init(&((queue)->mutex));                     \
} while (0)


/*
 * Initialize the message queue
 * params:
 *  - queue: a pointer, already allocated to a ovh_event_queue_t
 *  - mem_size (size): the number of item that the queue can have
 *  - entry_struct: the struct used to store the datas
 *
 *  This use tmc_spin_queued_mutex_t
 */
#define OVH_EVENT_QUEUE_INIT(queue, mem_size, entry_struct)          \
do {                                                                 \
  OVH_EVENT_QUEUE_INIT_WITH(queue, mem_size, entry_struct, OVH_AUTO_PAGED_ALLOCATOR, __not_used); \
} while (0)

/*
 */
#define OVH_EVENT_QUEUE_DISCARD(queue)          \
do {                                                                 \
  (queue)->size = 0;                                                 \
  (queue)->first = NULL;                                             \
  (queue)->last = NULL;                                              \
  OVH_MEMPOOL_DISCARD(*(queue)->mempool);                            \
  OVH_FREE_MAP((queue)->mempool, sizeof(ovh_mempool));                                            \
  (queue)->mempool = NULL;                                           \
} while (0)

/*
 * Get a free space to add a message
 * params:
 *  - queue: a pointer to a ovh_event_queue_t
 *  - entry: a NULL pointer, return the allowed space will be set to this pointer
 *
 *  This use tmc_spin_queued_mutex_t
 *  In case of failed, entry will be NULL after the call
 */
#define OVH_EVENT_QUEUE_GET_FREE(queue, entry)                      \
do {                                                                \
  (entry) = NULL;                                                   \
  OVH_MEMPOOL_ALLOC(*(queue)->mempool, (entry));                    \
  if ((entry) != NULL)                                              \
    (entry)->next = NULL;                                           \
} while(0)

/*
 * Push a message on the queue
 *
 * params:
 *  - queue: a pointer to a ovh_event_queue_t
 *  - entry: a pointer to allocated data, use OVH_EVENT_QUEUE_GET_FREE
 *
 *  This use tmc_spin_queued_mutex_t
 */
#define OVH_EVENT_QUEUE_PUSH(queue, entry, entry_struct)            \
do {                                                                \
  tmc_spin_queued_mutex_lock(&((queue)->mutex));                    \
  if ((queue)->first == NULL) {                                     \
    (queue)->first = (entry);                                       \
  }                                                                 \
  if ((queue)->last != NULL)                                        \
    ((entry_struct*)((queue)->last))->next = (entry);               \
  (queue)->last = (entry);                                          \
  (queue)->size += 1;                                               \
  (entry)->next = NULL;                                             \
  OVH_EVENT_QUEUE_LOCKED_CHECK(queue, entry_struct);                       \
  tmc_spin_queued_mutex_unlock(&((queue)->mutex));                  \
} while(0)

/*
 * Copy the message in the queue to a static array
 * params:
 *  - queue: a pointer to a ovh_event_queue_t
 *  - new_queue: a pointer to and ovh_event_queue_t which will be filled
 *
 *  This use tmc_spin_queued_mutex_t
 */
#define OVH_EVENT_QUEUE_COPY_AND_RESET(queue, new_queue)            \
do {                                                                \
  if ((queue)->size > 0) {                                          \
    tmc_spin_queued_mutex_lock(&((queue)->mutex));                  \
    (new_queue)->size = (queue)->size;                              \
    (new_queue)->first = (queue)->first;                            \
    (new_queue)->last = (queue)->last;                              \
    (new_queue)->mempool = (queue)->mempool;                        \
    (queue)->size = 0;                                              \
    (queue)->first = NULL;                                          \
    (queue)->last = NULL;                                           \
    tmc_spin_queued_mutex_unlock(&((queue)->mutex));                \
  }                                                                 \
  else {                                                            \
    (new_queue)->size = 0;                                          \
    (new_queue)->first = NULL;                                      \
    (new_queue)->last = NULL;                                       \
    (new_queue)->mempool = NULL;                                    \
  }                                                                 \
} while(0)

/*
 * Get the next pointer of a queue, and free the current
 * params:
 *  - queue: a pointer to ovh_event_queue_t
 *  - entry: the current element pointer
 *  - entry_struct: the struct used to store the datas
 *
 */
#define OVH_EVENT_QUEUE_FREE_GET_NEXT(queue, entry, entry_struct)   \
do {                                                                \
  entry_struct* next = (entry)->next;                               \
  OVH_MEMPOOL_FREE(*(queue)->mempool, (entry));                     \
  (entry) = next;                                                   \
} while(0);

/*
 * Initialize the message queue
 * params:
 *  - queue: a pointer, already allocated to a ovh_event_queue_t
 *  - mem_size (size): the number of item that the queue can have
 *  - entry_struct: the struct used to store the datas
 *
 *  This use pthread_mutex_t
 */
#define OVH_EVENT_QUEUE_PTHREAD_INIT(queue, mem_size, entry_struct)  \
do {                                                                 \
  (queue)->size = 0;                                                 \
  (queue)->first = NULL;                                             \
  (queue)->last = NULL;                                              \
  (queue)->mempool = OVH_MAP_CALLOC(1, sizeof(ovh_mempool));           \
  if ((queue)->mempool == NULL)                                      \
    tmc_task_die("Failed to allocate event_queue mempool object\n"); \
  OVH_MEMPOOL_CREATE(*(queue)->mempool, entry_struct, mem_size);     \
  if ((queue)->mempool->free == NULL)                                \
    tmc_task_die("Failed to allocate event_queue mempool\n");        \
  pthread_mutex_init(&((queue)->mutex), NULL);                       \
} while (0)

/*
 * Get a free space to add a message
 * params:
 *  - queue: a pointer to a ovh_event_queue_t
 *  - entry: a NULL pointer, return the allowed space will be set to this pointer
 *
 *  In case of failed, entry will be NULL after the call
 */
#define OVH_EVENT_QUEUE_PTHREAD_GET_FREE(queue, entry)              \
do {                                                                \
  (entry) = NULL;                                                   \
  OVH_MEMPOOL_ALLOC(*(queue)->mempool, (entry));                    \
  if ((entry) != NULL)                                              \
    (entry)->next = NULL;                                           \
} while(0)

/*
 * Push a message on the queue
 *
 * params:
 *  - queue: a pointer to a ovh_event_queue_t
 *  - entry: a pointer to allocated data, use OVH_EVENT_QUEUE_GET_FREE
 *
 *  This use pthread_mutex_t
 */
#define OVH_EVENT_QUEUE_PTHREAD_PUSH(queue, entry, entry_struct)    \
do {                                                                \
  pthread_mutex_lock(&((queue)->mutex));                            \
  if ((queue)->first == NULL) {                                     \
    (queue)->first = (entry);                                       \
  }                                                                 \
  if ((queue)->last != NULL)                                        \
    ((entry_struct*)((queue)->last))->next = (entry);               \
  (queue)->last = (entry);                                          \
  (queue)->size += 1;                                               \
  (entry)->next = NULL;                                             \
  OVH_EVENT_QUEUE_LOCKED_CHECK(queue, entry_struct);                       \
  pthread_mutex_unlock(&((queue)->mutex));                          \
} while(0)

/*
 * Copy the message in the queue to a static array
 * params:
 *  - queue: a pointer to a ovh_event_queue_t
 *  - new_queue: a pointer to and ovh_event_queue_t which will be filled
 *
 *  This use pthread_mutex_t
 */
#define OVH_EVENT_QUEUE_PTHREAD_COPY_AND_RESET(queue, new_queue)    \
do {                                                                \
  if ((queue)->size > 0) {                                          \
    pthread_mutex_lock(&((queue)->mutex));                          \
    (new_queue)->size = (queue)->size;                              \
    (new_queue)->first = (queue)->first;                            \
    (new_queue)->last = (queue)->last;                              \
    (new_queue)->mempool = (queue)->mempool;                        \
    (queue)->size = 0;                                              \
    (queue)->first = NULL;                                          \
    (queue)->last = NULL;                                           \
    pthread_mutex_unlock(&((queue)->mutex));                        \
  }                                                                 \
  else {                                                            \
    (new_queue)->size = 0;                                          \
    (new_queue)->first = NULL;                                      \
    (new_queue)->last = NULL;                                       \
    (new_queue)->mempool = NULL;                                    \
  }                                                                 \
} while(0)

/*
 * Get the next pointer of a queue, and free the current
 * params:
 *  - queue: a pointer to ovh_event_queue_t
 *  - entry: the current element pointer
 *  - entry_struct: the struct used to store the datas
 *
 */
#define OVH_EVENT_QUEUE_PTHREAD_FREE_GET_NEXT(queue, entry, entry_struct)   \
do {                                                                \
  entry_struct* next = (entry)->next;                               \
  OVH_MEMPOOL_FREE(*(queue)->mempool, (entry));                     \
  (entry) = next;                                                   \
} while(0);


#define OVH_EVENT_QUEUE_PRINT_USAGE(F, Q) \
do { \
 int char_count = fprintf(F, #Q ""); \
 FPRINTF_SPACE(F, 37 - char_count); \
 uint32_t items_used = (Q).size; \
 fprintf(F, " | %8u \n", items_used);\
} while(0)

#endif /* !OVH_EVENT_QUEUE_H_ */
