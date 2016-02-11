#ifndef __OVH_TIME_H__
#define __OVH_TIME_H__

#include "ovh_defines.h"
#include "ovh_log.h"
#include "ovh_types.h"

extern struct timeval ovh_cur_time;
extern uint64_t ovh_cur_time_ms;

#define OVH_CUR_TIME_MS ovh_cur_time_ms
#define OVH_UPDATE_CUR_TIME() \
do {  \
  gettimeofday(&ovh_cur_time, NULL); \
  ovh_cur_time_ms = (uint64_t)((ovh_cur_time.tv_sec * 1000) + (ovh_cur_time.tv_usec / 1000)); \
} while(0)


#endif //__OVH_TIME_H__
