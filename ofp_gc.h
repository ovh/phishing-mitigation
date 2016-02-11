#ifndef __OFP_GC_H__
#define __OFP_GC_H__

//=======================================================================================================
// Read-write lock for garbage_collector & logger
// Since garbage_collector is the only one freeing data from hashes,
// we only need a lock between the GC and the logger to ensure that the logger will not access freed data
//=======================================================================================================
extern pthread_mutex_t mutex_gc;


void* garbage_collector(void* arg);

#endif //__OFP_GC_H__
