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
#include "ofp_phish_target_ip_ht.h"
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

static void ofp_phish_target_by_ip_copy_test(void** state)
{
  (void)state;

  CHECK_ZERO_MEMORY_ALLOCATED;

  //set to 0, to prevent valgrind from complaining about padding memory not unitialized during hash computing
  ip_port_tuple ip_port = {0};
  ip_port.ip = 1234;
  ip_port.port = 80;

  ofp_phish_target_ip_ht_t* srcHash = config_ip_hash;
  ofp_phish_target_ip_ht_locked_t srclocked = ofp_phish_target_by_ip_lock(srcHash);
  int rank = 0;
  ofp_phish_target_ip_ht_t* workerHash = ofp_phish_target_by_ip_get(rank);
  ofp_phish_target_ip_ht_locked_t workerLocked = ofp_phish_target_by_ip_lock(workerHash);

  ofp_phish_target_ip_t* data = ofp_phish_target_by_ip_insert(srclocked, ofp_phish_target_ip_new_init(ip_port));
  assert_non_null(data);
  assert_int_equal(1, OVH_HASH_COUNT(srclocked.hash));
  assert_int_equal(0, OVH_HASH_COUNT(workerLocked.hash));

  int result = ofp_phish_target_by_ip_copy(workerLocked, srclocked);
  assert_int_equal(1, result);
  assert_int_equal(1, OVH_HASH_COUNT(srclocked.hash));
  assert_int_equal(1, OVH_HASH_COUNT(workerLocked.hash));


  ofp_phish_target_by_ip_free_elements(srclocked);
  ofp_phish_target_by_ip_unlock(srclocked);

  ofp_phish_target_by_ip_free_elements(workerLocked);
  ofp_phish_target_by_ip_unlock(workerLocked);

  CHECK_ZERO_MEMORY_ALLOCATED;
}


static void phish_target_by_ip_add_and_find_test(void** state)
{
  (void)state;

  CHECK_ZERO_MEMORY_ALLOCATED;

  //set to 0, to prevent valgrind from complaining about padding memory not unitialized during hash computing
  ip_port_tuple ip_port = {0};
  ip_port.ip = 1234;
  ip_port.port = 80;

  int rank = 0;
  ofp_phish_target_ip_ht_t* hash = ofp_phish_target_by_ip_get(rank);

  ofp_phish_target_ip_ht_locked_t locked = ofp_phish_target_by_ip_lock(hash);

  ofp_phish_target_ip_t* data = ofp_phish_target_by_ip_find(locked, ip_port);
  assert_null(data);

  ofp_phish_target_ip_t* target = ofp_phish_target_ip_new_init(ip_port);
  data = ofp_phish_target_by_ip_insert(locked, target);
  assert_non_null(data);
  assert_int_equal(1, OVH_HASH_COUNT(hash));

  ofp_phish_target_by_ip_free_elements(locked);
  assert_int_equal(0, OVH_HASH_COUNT(locked.hash));

  data = ofp_phish_target_by_ip_upsert(locked, ip_port);
  assert_non_null(data);
  assert_int_equal(1, OVH_HASH_COUNT(hash));

  data = ofp_phish_target_by_ip_find(locked, ip_port);
  assert_non_null(data);
  assert_int_equal(data->ipPort.ip, ip_port.ip);
  assert_int_equal(data->ipPort.port, ip_port.port);

  ofp_phish_target_by_ip_free_elements(locked);
  ofp_phish_target_by_ip_unlock(locked);

  assert_int_equal(0, OVH_HASH_COUNT(hash)); //all removed ?

  CHECK_ZERO_MEMORY_ALLOCATED;
}

static const struct CMUnitTest tests[] = {
  cmocka_unit_test(phish_target_by_ip_add_and_find_test),
  cmocka_unit_test(ofp_phish_target_by_ip_copy_test),
};

SUPPRESS_UNUSED_WARN(phish_target_by_ip_add_and_find_test);
SUPPRESS_UNUSED_WARN(ofp_phish_target_by_ip_copy_test);

test_helper_group(tests, suite_setup, suite_teardown);

