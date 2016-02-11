#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <stdint.h>

#include "cmocka.h"
#include "test_data.h"
#include "ovh_common.h"
#include "ofp_defines.h"
#include "ofp_config_ip.h"
#include "ofp_event_http_match.h"

#define REDBAR \
"=======================\n\
\t\033[31mRED BAR!\033[0m\n\
=======================\n"

#define GREENBAR \
"==========================\n\
\t\033[32mGREEN BAR!\033[0m\n\
==========================\n"

#if REGEX
#define CHECK_REGEX_ZERO_MEMORY_ALLOCATED()  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*ovh_regex_mempool))
#else
#define CHECK_REGEX_ZERO_MEMORY_ALLOCATED() do { } while(0)
#endif


#define CHECK_ZERO_MEMORY_ALLOCATED                                       \
do {                                                                      \
  assert_int_equal(0, OVH_HASH_COUNT(config_desc_hash));             \
  assert_int_equal(0, OVH_HASH_COUNT(config_host_hash));                  \
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*event_queue_http_match.mempool));     \
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*phish_desc_mempool));     \
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*phish_target_mempool));     \
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*phish_target_ip_mempool));  \
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*ofp_uri_list_pool));        \
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*ofp_uri_list_entry_pool));  \
  CHECK_REGEX_ZERO_MEMORY_ALLOCATED();                                      \
} while(0)



#define test_helper_group(group, setup, teardown) \
__attribute__((constructor)) \
static void __group_constructor(void) { \
  test_helper_report_failed(cmocka_run_group_tests(group, setup, teardown)); \
}

void test_helper_report_failed(int count);

#include <arpa/inet.h>
#define assert_ipv4_equal_host(expected_ip_str, ip) do { \
  typeof(expected_ip_str) __check_is_string = "";   \
  (void )__check_is_string;                         \
  struct in_addr expected_src_addr;                 \
  assert_non_null(expected_ip_str);                 \
  int parse_ok = inet_pton(AF_INET, expected_ip_str, &expected_src_addr); \
  assert_int_equal(1, parse_ok);                    \
  assert_int_equal(expected_src_addr.s_addr, ntohl(ip));   \
} while(0)

