#ifndef __OVH_LOG_H__
#define __OVH_LOG_H__

#include "ovh_defines.h"
#include "ovh_tmc.h"

// =========================================================================================
// Misc
// =========================================================================================
void printHex(uint8_t* data, uint32_t size);

// =========================================================================================
// Debug printing
// =========================================================================================
void debug_printf(const char* prefix, const char *fileName, const char *function, int line, const char *fmt, ...);

#define FPRINTF_SPACE(__file__, __count__) \
do { \
  if ((__count__) > 0) \
  fprintf((__file__), "%*c", (__count__), ' '); \
} while(0)


#define PRINT_INFO(...) debug_printf("INFO", NULL, NULL, 0, __VA_ARGS__)
#define PRINT_DEBUG(...) debug_printf("DEBUG", __FILE__, __func__, __LINE__, __VA_ARGS__)
#define PRINT_ERR(...) debug_printf("ERROR", __FILE__, __func__, __LINE__, __VA_ARGS__)
#define NO_PRINT do {} while(0)

#if DEBUG == 5
#define PRINT_D5(...) PRINT_DEBUG(__VA_ARGS__)
#else
#define PRINT_D5(...) NO_OP(__VA_ARGS__)
#endif
#if DEBUG >= 4
#define PRINT_D4(...) PRINT_DEBUG(__VA_ARGS__)
#else
#define PRINT_D4(...) NO_OP(__VA_ARGS__)
#endif
#if DEBUG >= 3
#define PRINT_D3(...) PRINT_DEBUG(__VA_ARGS__)
#else
#define PRINT_D3(...) NO_OP(__VA_ARGS__)
#endif
#if DEBUG >= 2
#define PRINT_D2(...) PRINT_DEBUG(__VA_ARGS__)
#else
#define PRINT_D2(...) NO_OP(__VA_ARGS__)
#endif
#if DEBUG == 1
#define PRINT_D1(...) printf(__VA_ARGS__)
#else
#define PRINT_D1(...) NO_OP(__VA_ARGS__)
#endif

//Be sure to inlcude this file BEFORE uthash.h
#define uthash_fatal(msg) PRINT_D5(msg)

// =========================================================================================
// Assertions
// =========================================================================================
#if DEBUG > 0
#define OVH_ASSERT(COND)\
do {\
  if(!(COND)) {\
    log_backtrace(); \
    TMC_TASK_DIE("Assert failed : %s\n", #COND);\
  }\
} while(0)

#else
#define OVH_ASSERT(COND) do { (void)sizeof(COND); } while(0)
#endif //DEBUG

// Help check for errors.
#define VERIFY(VAL, WHAT)                                       \
  do {                                                          \
    long long __val = (VAL);                                    \
    if (__val < 0)                                              \
      TMC_TASK_DIE("Failure in '%s': %lld: %s.",(WHAT), __val, gxio_strerror(__val)); \
  } while (0)


// =========================================================================================
// Format
// =========================================================================================
extern const char bytes_units[];
void format_human(long bytes, char *buf);
void log_backtrace();


// =========================================================================================
// HASH_STATS
// =========================================================================================
#if OVH_HASH_STATS
#define RECOMPUTE_STATS(HT) OVH_HASH_COMPUTE_STATS(HT)
#define OVH_HASH_PRINT_LINE(__file, __usagePercent, __countSum, __chain1Sum, __chain2Sum, __chain4Sum, __chain8Sum, __bucketSum) fprintf(__file, " | %6.3f%% |(%8d)|(%8d)|(%8d)|(%8d)|(%8d)|(%8u)\n", __usagePercent, __countSum, __chain1Sum, __chain2Sum, __chain4Sum, __chain8Sum, __bucketSum)
#else
#define RECOMPUTE_STATS(HT)
#define OVH_HASH_PRINT_LINE(__file, __usagePercent, __countSum, __chain1Sum, __chain2Sum, __chain4Sum, __chain8Sum, __bucketSum) fprintf(__file, " | %6.3f%% |(%8d)|             OVH_HASH_STATS==0             |(%8u)\n", __usagePercent, __countSum, __bucketSum)
#endif //OVH_HASH_STATS

#define OVH_LOG_HASH_TABLE(F, HT, __hash_usage)           \
do {                                                      \
    int char_count = fprintf(F, "HT " #HT "");            \
    FPRINTF_SPACE(F, 37 - char_count);                    \
  if((HT) != NULL) {                                      \
    __hash_usage = OVH_HASH_USAGE(HT);                    \
    RECOMPUTE_STATS(HT);                                  \
    OVH_HASH_PRINT_LINE(F, 100.0f * __hash_usage, OVH_HASH_COUNT(HT), OVH_HASH_CHAIN_COUNT(HT, 1), OVH_HASH_CHAIN_COUNT(HT, 2), OVH_HASH_CHAIN_COUNT(HT, 4), OVH_HASH_CHAIN_COUNT(HT, 8), OVH_HASH_NUM_BUCKETS(HT));               \
  }                                                       \
  else {                                                  \
    fprintf(F, "(null) \n");                              \
  }                                                       \
}while(0)


#define OVH_HASH_PRINT_AGGREGATED_USAGE(__file, __hash_type, __items, __items_count, __items_accessor, __with_hash_stats)                   \
do {                                                                                              \
  double usageMax = 0.0;                                                                          \
  uint32_t countSum = 0;                                                                          \
  uint32_t chain1Sum = 0;                                                                         \
  uint32_t chain2Sum = 0;                                                                         \
  uint32_t chain4Sum = 0;                                                                         \
  uint32_t chain8Sum = 0;                                                                         \
  uint32_t chain16Sum = 0;                                                                        \
  uint32_t bucketSum = 0;                                                                         \
  int detailLogLineCount = 0;                                                                     \
  (void)detailLogLineCount;                                                                       \
  if (__file != NULL) {                                                                           \
    for (int __i = 0; __i < __items_count; ++__i) {                                               \
      __hash_type* hash = __items_accessor;                                                       \
      RECOMPUTE_STATS(hash);                                                                      \
      double usage = OVH_HASH_USAGE(hash);                                                            \
      if(__with_hash_stats) {                                                                     \
        if(usage > 0.50f && detailLogLineCount < 32) {                                            \
          int char_count = fprintf(file, "HT %s#%d", #__items, __i);                          \
          FPRINTF_SPACE(file, 37 - char_count);                                                   \
          fprintf(file, " | %6.3f%% | %8d | %8d | %8d | %8d | %8d | %8u \n", usage * 100.0f, OVH_HASH_COUNT(hash), OVH_HASH_CHAIN_COUNT(hash, 1), OVH_HASH_CHAIN_COUNT(hash, 2), OVH_HASH_CHAIN_COUNT(hash, 4), OVH_HASH_CHAIN_COUNT(hash, 8), OVH_HASH_NUM_BUCKETS(hash)); \
          detailLogLineCount++;                                                                   \
        }                                                                                         \
      }                                                                                           \
      if(usage > usageMax) usageMax = usage;                                                      \
      countSum += OVH_HASH_COUNT(hash);                                                               \
      chain1Sum += OVH_HASH_CHAIN_COUNT(hash, 1);                                                     \
      chain2Sum += OVH_HASH_CHAIN_COUNT(hash, 2);                                                     \
      chain4Sum += OVH_HASH_CHAIN_COUNT(hash, 4);                                                     \
      chain8Sum += OVH_HASH_CHAIN_COUNT(hash, 8);                                                     \
      chain16Sum += OVH_HASH_CHAIN_COUNT(hash, 16);                                                   \
      bucketSum += OVH_HASH_NUM_BUCKETS(hash);                                                        \
    }                                                                                             \
    int char_count = fprintf(file, "HT %s", #__items);                                        \
    FPRINTF_SPACE(file, 37 - char_count);                                                         \
    OVH_HASH_PRINT_LINE(file, usageMax * 100.0f, countSum, chain1Sum, chain2Sum, chain4Sum, chain8Sum, bucketSum);  \
  }                                                                                               \
} while(0)




#endif //__OVH_LOG_H__
