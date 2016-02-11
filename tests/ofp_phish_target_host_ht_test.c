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
#include "ofp_phish_target_host_ht.h"
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

static void phish_target_ht_add_and_find_test(void** state)
{
  (void)state;
  CHECK_ZERO_MEMORY_ALLOCATED;

  char* host = "example.com";
  int rank = 0;
  ofp_phish_target_host_ht_t* hash = ofp_phish_target_by_host_get(rank);

  ofp_phish_target_host_ht_locked_t locked = ofp_phish_target_by_host_lock(hash);

  ofp_phish_target_host_t* data = ofp_phish_target_by_host_find(locked, host);
  assert_null(data);

  ofp_phish_target_host_t* target = ofp_phish_target_new_dup(host);
  ofp_phish_target_by_host_insert(locked, target);
  assert_int_equal(1, OVH_HASH_COUNT(locked.hash));

  data = ofp_phish_target_by_host_find(locked, host);
  assert_non_null(data);
  assert_string_equal(data->host, host);
  ofp_uri_list_entry_add_uri(data->uriList, strdup("/index.html"));
  assert_int_equal(1, data->uriList->count);

  ofp_phish_target_host_ht_t* copyHash = ofp_phish_target_by_host_get(rank+1);
  ofp_phish_target_host_ht_locked_t copyLocked = ofp_phish_target_by_host_lock(copyHash);
  int result = ofp_phish_target_by_host_copy(copyLocked, locked);
  assert_int_equal(1, result);
  assert_int_equal(1, OVH_HASH_COUNT(copyLocked.hash));
  data = ofp_phish_target_by_host_find(copyLocked, host);
  assert_non_null(data);
  assert_string_equal(data->host, host);
  assert_int_equal(1, data->uriList->count);

  ofp_phish_target_by_host_free_elements(copyLocked);
  ofp_phish_target_by_host_unlock(copyLocked);

  ofp_phish_target_by_host_free_elements(locked);
  ofp_phish_target_by_host_unlock(locked);

  assert_int_equal(0, OVH_HASH_COUNT(hash)); //all removed ?
  CHECK_ZERO_MEMORY_ALLOCATED;
}

static const struct CMUnitTest tests[] = {
  cmocka_unit_test(phish_target_ht_add_and_find_test),
};

test_helper_group(tests, suite_setup, suite_teardown);

SUPPRESS_UNUSED_WARN(phish_target_ht_add_and_find_test);
