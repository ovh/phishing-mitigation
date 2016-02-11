/*
 Copyright (C) 2016, OVH SAS

 This file is part of phishing-mitigation.

 phishing-mitigation is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "tests_helpers.h"
#include "ofp_config_ip.h"
#include "ofp_phish.h"
#include "ofp_init.h"

static int suite_setup(void **state) {
  int workerCount = 29;
  ofp_init(workerCount, 0);
  ofp_init_alloc_shared(NULL);
  return 0;
}

static int suite_teardown(void **state) {
  ofp_free_shared();
  ofp_close();
  return 0;
}

/*
* Test phishing url parsing :
* Extract ip + hostname + uri
* 192.168.10.1 http://www.example.com/index.html sould return :
* ip as int
* example.com (www. should be removed)
* /index.html
*/
static void config_ip_parse_phishing_target_test(void** state)
{
  (void)state;

  CHECK_ZERO_MEMORY_ALLOCATED;

  const char* value = "192.168.10.1 http://www.example.com/index.html";
  ofp_phish_target_host_t* desc = config_ip_target_parse(config_host_hash, config_ip_hash, value, str_to_target_type("x"), 0);
  assert_non_null(desc);
  assert_string_equal("example.com", desc->host);
  assert_int_equal(1, desc->uriList->count);
  assert_string_equal("/index.html", desc->uriList->head->uri);

  value = "192.168.10.1 http://www.example.com:80/index.html";
  desc = config_ip_target_parse(config_host_hash, config_ip_hash, value, str_to_target_type("x"), 0);
  assert_non_null(desc);
  assert_string_equal("example.com", desc->host);
  assert_int_equal(2, desc->uriList->count); //may be we need to keep port in host name so we can split different port into different target ?
  assert_string_equal("/index.html", desc->uriList->head->uri);

  value = "192.168.10.1 http://www.example.com:8080/index.html";
  desc = config_ip_target_parse(config_host_hash, config_ip_hash, value, str_to_target_type("x"), 0);
  assert_non_null(desc);
  assert_string_equal("example.com:8080", desc->host);
  assert_int_equal(1, desc->uriList->count);
  assert_string_equal("/index.html", desc->uriList->head->uri);

  value = "192.168.10.1 www.example.com:8080/index.html";
  desc = config_ip_target_parse(config_host_hash, config_ip_hash, value, str_to_target_type("x"), 0);
  assert_non_null(desc);
  assert_string_equal("example.com:8080", desc->host);
  assert_int_equal(2, desc->uriList->count);
  assert_string_equal("/index.html", desc->uriList->head->uri);

  value = "192.168.10.1 192.168.10.1:8080/index.html";
  desc = config_ip_target_parse(config_host_hash, config_ip_hash, value, str_to_target_type("x"), 0);
  assert_non_null(desc);
  assert_string_equal("192.168.10.1:8080", desc->host);
  assert_int_equal(1, desc->uriList->count);
  assert_string_equal("/index.html", desc->uriList->head->uri);

  ofp_phish_target_ip_ht_locked_t config_ip_locked = ofp_phish_target_by_ip_lock(config_ip_hash);
  ofp_phish_target_by_ip_free_elements(config_ip_locked);
  ofp_phish_target_by_ip_unlock(config_ip_locked);

  ofp_phish_target_host_ht_locked_t config_host_locked = ofp_phish_target_by_host_lock(config_host_hash);
  ofp_phish_target_by_host_free_elements(config_host_locked);
  ofp_phish_target_by_host_unlock(config_host_locked);

  CHECK_ZERO_MEMORY_ALLOCATED;
}

/*
* Parse a set of lines
* lines with same hostname should be aggregated in same target
* Also test a hash copy and clear, there should be no leak
*/
static void config_ip_parse_lines_copy_and_clear_test(void** state)
{
  (void)state;
  CHECK_ZERO_MEMORY_ALLOCATED;
  int result;
  const char* lines[] =
  {
    "x 192.168.10.1 http://www.example1.com/index.html",
    "x 192.168.10.2 http://www.example2.com/phish.html",
    "x 192.168.10.2 http://www.example2.com/phish/index.php?var=value&p",
  };
  const int lineCount = sizeof(lines) / sizeof(char*);
  ip_port_tuple ip1;
  result = parse_ip("192.168.10.1", 0, &ip1);
  assert_int_equal(1, result);
  assert_ipv4_equal_host("192.168.10.1", ip1.ip);
  ip_port_tuple ip2;
  result = parse_ip("192.168.10.2", 0, &ip2);
  assert_int_equal(1, result);
  assert_ipv4_equal_host("192.168.10.2", ip2.ip);


  ofp_phish_desc_hash_table_locked_t config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);
  //int result = config_ip_desc_add_file(config_desc_locked, "../conf/ip.conf");
  result = config_ip_desc_add_lines(config_desc_locked, (const char** )lines, lineCount);
  result &= config_ip_target_parse_desc_ht(config_host_hash, config_ip_hash, config_desc_locked);
  ofp_phish_desc_ht_free_elements(config_desc_locked);
  ofp_phish_desc_ht_unlock(config_desc_locked);
  assert_int_equal(1, result);

  ofp_phish_target_host_ht_locked_t config_host_locked = ofp_phish_target_by_host_lock(config_host_hash);

  ofp_phish_target_host_t *target=NULL;
  ofp_uri_list_entry_t* uriEntry = NULL;

  target = ofp_phish_target_by_host_find(config_host_locked, "example1.com");
  assert_non_null(target);
  assert_string_equal("example1.com", target->host);
  assert_int_equal(1, target->uriList->count);
  assert_string_equal("/index.html", target->uriList->head->uri);

  target = ofp_phish_target_by_host_find(config_host_locked, "example2.com");
  assert_non_null(target);
  assert_string_equal("example2.com", target->host);
  assert_int_equal(2, target->uriList->count);
  uriEntry = target->uriList->head;
  int index = 0;
  while(uriEntry != NULL)
  {
    if(index == 0) assert_string_equal("/phish.html", uriEntry->uri);
    if(index == 1) assert_string_equal("/phish/index.php?var=value&p", uriEntry->uri);

    uriEntry = uriEntry->next;
    index++;
  }

  //Test copy ht
  ofp_phish_target_host_ht_t* copyHash = ofp_phish_target_by_host_get(0);
  ofp_phish_target_host_ht_locked_t copyLocked = ofp_phish_target_by_host_lock(copyHash);
  result = ofp_phish_target_by_host_copy(copyLocked, config_host_locked);
  assert_int_equal(1, result);
  ofp_phish_target_by_host_free_elements(copyLocked);
  ofp_phish_target_by_host_unlock(copyLocked);

  ofp_phish_target_ip_ht_locked_t config_ip_locked = ofp_phish_target_by_ip_lock(config_ip_hash);
  assert_int_equal(2, OVH_HASH_COUNT(config_ip_locked.hash));
  ofp_phish_target_ip_t* targetIp = ofp_phish_target_by_ip_find(config_ip_locked, ip1);
  assert_non_null(targetIp);
  targetIp = ofp_phish_target_by_ip_find(config_ip_locked, ip2);
  assert_non_null(targetIp);


  ofp_phish_target_by_ip_free_elements(config_ip_locked);
  ofp_phish_target_by_ip_unlock(config_ip_locked);

  ofp_phish_target_by_host_free_elements(config_host_locked);
  ofp_phish_target_by_host_unlock(config_host_locked);

  CHECK_ZERO_MEMORY_ALLOCATED;
}

/*
* Test only read lines describing targets from file
*/
static void config_ip_desc_file_test(void** state)
{
  (void)state;
  CHECK_ZERO_MEMORY_ALLOCATED;

  ofp_phish_desc_hash_table_locked_t config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);
  int result = config_ip_desc_add_file(config_desc_locked, "../conf/ip.conf");
  ofp_phish_desc_ht_unlock(config_desc_locked);

  assert_int_equal(1, result);
  assert_int_equal(6, OVH_HASH_COUNT(config_desc_hash)); //in conf file we setted 3 different hostname

  ofp_phish_desc_t *desc=NULL, *tmp=NULL;
  int index = 0;
  OVH_HASH_ITER(config_desc_hash, desc, tmp)
  {
    assert_non_null(desc);
    assert_non_null(desc->data);
    //printf("(%s)\n", desc->data);
    if(index == 0) assert_string_equal("x 10.254.0.8 http://www.example.com/index.html", desc->data);
    index++;
  }

  config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);
  ofp_phish_desc_ht_free_elements(config_desc_locked);
  ofp_phish_desc_ht_unlock(config_desc_locked);

  CHECK_ZERO_MEMORY_ALLOCATED;
}


/*
* Test full read & parse from file
*/
static void config_ip_parse_file_test(void** state)
{
  (void)state;
  CHECK_ZERO_MEMORY_ALLOCATED;

  ofp_phish_desc_hash_table_locked_t config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);
  int result = config_ip_desc_add_file(config_desc_locked, "../conf/ip.conf");
  result &= config_ip_target_parse_desc_ht(config_host_hash, config_ip_hash, config_desc_locked);
  ofp_phish_desc_ht_free_elements(config_desc_locked);
  ofp_phish_desc_ht_unlock(config_desc_locked);

  assert_int_equal(1, result);
  int hostCountExpected = 2;
#if REGEX
  hostCountExpected = 3;
#endif
  assert_int_equal(hostCountExpected, OVH_HASH_COUNT(config_host_hash)); //in conf file we setted 3 different hostname

  ofp_phish_target_host_t *target=NULL, *tmp=NULL;
  OVH_HASH_ITER(config_host_hash, target, tmp)
  {
    assert_non_null(target);
    assert_int_equal(2, target->uriList->count); //in conf file we setted 2 uris per host
    ofp_uri_list_entry_t* entry = target->uriList->head;
    int index = 0;
    //check list consistency
    while(entry != NULL)
    {
      assert_true(index < 2);
      entry = entry->next;
      index++;
    }
    assert_int_equal(2, index);
  }

  ofp_phish_target_host_ht_locked_t config_host_locked = ofp_phish_target_by_host_lock(config_host_hash);
  ofp_phish_target_by_host_free_elements(config_host_locked);
  ofp_phish_target_by_host_unlock(config_host_locked);

  ofp_phish_target_ip_ht_locked_t config_ip_locked = ofp_phish_target_by_ip_lock(config_ip_hash);
  ofp_phish_target_by_ip_free_elements(config_ip_locked);
  ofp_phish_target_by_ip_unlock(config_ip_locked);


  CHECK_ZERO_MEMORY_ALLOCATED;
}


static void config_ip_parse_delta_desc(void** state)
{
  (void)state;
  CHECK_ZERO_MEMORY_ALLOCATED;

  ofp_phish_desc_hash_table_locked_t config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);

  config_ip_desc_parse_delta_line(config_desc_locked, "+x 10.254.0.8 http://www.example.com/newone.html\r", 0);
  assert_int_equal(1, OVH_HASH_COUNT(config_desc_hash));
  ofp_phish_desc_t* desc = ofp_phish_desc_ht_find(config_desc_locked, "x 10.254.0.8 http://www.example.com/newone.html");
  assert_non_null(desc);
  assert_string_equal("x 10.254.0.8 http://www.example.com/newone.html", desc->data);
  config_ip_desc_parse_delta_line(config_desc_locked, "+x 10.254.0.8 http://www.example.com/newone.html", 0);
  assert_int_equal(1, OVH_HASH_COUNT(config_desc_hash)); //same line, should not increase entries count

  desc=NULL;
  ofp_phish_desc_t* tmp=NULL;
  OVH_HASH_ITER(config_desc_hash, desc, tmp)
  {
    assert_non_null(desc);
    assert_string_equal("x 10.254.0.8 http://www.example.com/newone.html", desc->data);
  }

  config_ip_desc_parse_delta_line(config_desc_locked, "-x 10.254.0.8 http://www.example.com/newone.html", 0);
  assert_int_equal(0, OVH_HASH_COUNT(config_desc_hash)); //after remove, entry count should reach 0

  ofp_phish_desc_ht_free_elements(config_desc_locked);
  ofp_phish_desc_ht_unlock(config_desc_locked);

  CHECK_ZERO_MEMORY_ALLOCATED;
}

/*
* Test case like google.com where one hostname can use multiple Ip
*/
static void config_ip_one_host_with_multiple_ip_test(void** state)
{
  (void)state;

  CHECK_ZERO_MEMORY_ALLOCATED;

  const char* value = "192.168.10.1 http://www.example.com/index.html";
  ofp_phish_target_host_t* desc = config_ip_target_parse(config_host_hash, config_ip_hash, value, TargetURI, 0);
  assert_non_null(desc);
  assert_string_equal("example.com", desc->host);
  assert_int_equal(1, desc->uriList->count);
  assert_string_equal("/index.html", desc->uriList->head->uri);



  ofp_phish_target_host_ht_locked_t config_host_locked = ofp_phish_target_by_host_lock(config_host_hash);
  ofp_phish_target_by_host_free_elements(config_host_locked);
  ofp_phish_target_by_host_unlock(config_host_locked);

  ofp_phish_target_ip_ht_locked_t config_ip_locked = ofp_phish_target_by_ip_lock(config_ip_hash);
  ofp_phish_target_by_ip_free_elements(config_ip_locked);
  ofp_phish_target_by_ip_unlock(config_ip_locked);


  CHECK_ZERO_MEMORY_ALLOCATED;
}



static const struct CMUnitTest tests[] = {
  cmocka_unit_test(config_ip_parse_lines_copy_and_clear_test),
  cmocka_unit_test(config_ip_parse_phishing_target_test),
  cmocka_unit_test(config_ip_desc_file_test),
  cmocka_unit_test(config_ip_parse_file_test),
  cmocka_unit_test(config_ip_parse_delta_desc),
  cmocka_unit_test(config_ip_one_host_with_multiple_ip_test),
};

test_helper_group(tests, suite_setup, suite_teardown);


SUPPRESS_UNUSED_WARN(suite_setup);
SUPPRESS_UNUSED_WARN(suite_teardown);
SUPPRESS_UNUSED_WARN(config_ip_parse_phishing_target_test);
SUPPRESS_UNUSED_WARN(config_ip_parse_lines_copy_and_clear_test);
SUPPRESS_UNUSED_WARN(config_ip_desc_file_test);
SUPPRESS_UNUSED_WARN(config_ip_parse_file_test);
SUPPRESS_UNUSED_WARN(config_ip_parse_delta_desc);
SUPPRESS_UNUSED_WARN(config_ip_one_host_with_multiple_ip_test);

