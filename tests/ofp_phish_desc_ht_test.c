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
#include <stdio.h>
#include <signal.h>

#include "tests_helpers.h"
#include "ofp_phish_desc_ht.h"
#include "ofp_config_ip.h"
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

static void phish_desc_ht_upsert_and_remove_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;
  (void)state;
  ofp_phish_desc_hash_table_t* hash = config_desc_hash;

  //init state ok ?
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*phish_desc_mempool));
  assert_int_equal(0, OVH_HASH_COUNT(hash));

  ofp_phish_desc_hash_table_locked_t locked = ofp_phish_desc_ht_lock(hash);

  //============
  //upsert
  //============
  ofp_phish_desc_ht_upsert(locked, "foo");                  //add "foo"
  ofp_phish_desc_ht_upsert(locked, "bar");                  //add "bar"
  assert_int_equal(2, OVH_HASH_COUNT(locked.hash));              //count ok ?

  ofp_phish_desc_t* entry = ofp_phish_desc_ht_find(locked, "foo");
  assert_non_null(entry);                                   //"foo" is present in ht ?
  assert_string_equal("foo", entry->data);                  //good data ?

  entry = ofp_phish_desc_ht_find(locked, "bar");
  assert_non_null(entry);                                   //"foo" is present in ht ?
  assert_string_equal("bar", entry->data);                  //good data ?


  int result = ofp_phish_desc_ht_free(locked, "foo");     //remove "foo"
  assert_int_equal(1, result);                              //remove succeed
  assert_int_equal(1, OVH_HASH_COUNT(locked.hash));              //count-- ?
  entry = ofp_phish_desc_ht_find(locked, "foo");
  assert_null(entry);

  result = ofp_phish_desc_ht_free(locked, "foo");         //try remove it again
  assert_int_equal(0, result);                              //should have failed !

  //clear
  ofp_phish_desc_ht_free_elements(locked);
  assert_int_equal(0, OVH_HASH_COUNT(locked.hash)); //all removed ?


  //============
  //insert
  //============
  ofp_phish_desc_ht_insert(locked, "baz");
  assert_int_equal(1, OVH_HASH_COUNT(locked.hash));
  entry = ofp_phish_desc_ht_find(locked, "baz");
  assert_non_null(entry);                                   //"foo" is present in ht ?
  assert_string_equal("baz", entry->data);                  //good data ?

  ofp_phish_desc_ht_free_elements(locked);
  assert_int_equal(0, OVH_HASH_COUNT(locked.hash)); //all removed ?



  ofp_phish_desc_ht_unlock(locked);


  CHECK_ZERO_MEMORY_ALLOCATED;
}

static const struct CMUnitTest tests[] = {
  cmocka_unit_test(phish_desc_ht_upsert_and_remove_test),
};

test_helper_group(tests, suite_setup, suite_teardown);

SUPPRESS_UNUSED_WARN(phish_desc_ht_upsert_and_remove_test);
