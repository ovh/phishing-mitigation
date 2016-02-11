#ifndef __OVH_CPU_H__
#define __OVH_CPU_H__

#include "ovh_defines.h"
#include "ovh_log.h"
#include "ovh_tmc.h"

extern cpu_set_t normal_cpus;
extern cpu_set_t dataplane_cpus;

void ovh_cpu_init(int work_size);

#endif //__OVH_CPU_H__
