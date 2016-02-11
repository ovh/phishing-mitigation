#ifndef _OVH_DEFINE_H_
#define _OVH_DEFINE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>

#define INLINE inline __attribute__((always_inline))

#ifndef TMC
#error TMC not defined, check your Makefile
#endif

#ifndef DEBUG
#define DEBUG 0
#endif

#ifndef REGEX
#define REGEX 0
#endif

#ifndef SOCKET
#define SOCKET 0
#endif

#ifndef OVH_LOG_ALLOC
#define OVH_LOG_ALLOC 0
#endif

#ifndef OVH_MEMPOOL_HUGEPAGES
#define OVH_MEMPOOL_HUGEPAGES 0
#endif

#ifndef OVH_HASH_STATS
#define OVH_HASH_STATS 0
#endif



#define SUPPRESS_UNUSED_WARN(var) int* _dummy_tmp_##var = (int *)(void *)(var)
#define SUPPRESS_UNUSED_VAR_WARN(var) (void )(var)
#define UNUSED(expr) do { (void)(expr); } while (0)
#define NO_OP(...) do { if(0) debug_printf(NULL, NULL, NULL, 0, __VA_ARGS__); } while(0) //Trick so gcc won't complain about unused variables when the project is build with DEBUG=0

#define OVH_STR_START_WITH(data, dataLen, prefix) OVH_STR_START_WITH_2(data, dataLen, prefix, strlen(prefix))
#define OVH_STR_START_WITH_2(data, dataLen, prefix, prefixLen) (dataLen >= prefixLen && strncmp(data, prefix, prefixLen) == 0)

#define OVH_STR_EQUAL(data, dataLen, otherData) OVH_STR_EQUAL_2(data, dataLen, otherData, strlen(otherData))
#define OVH_STR_EQUAL_2(data, dataLen, other, otherLen) (dataLen == otherLen && strncmp(data, other, dataLen) == 0)

#define TODO 0

#ifndef BIG_ENDIAN //TODO automatically chose endianness from platform target
#define BIG_ENDIAN 1
#endif

#define OVH_MAX(a, b)\
  ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define OVH_MIN(a, b)\
  ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#endif //_OVH_DEFINE_H_
