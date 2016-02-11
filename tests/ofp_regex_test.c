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
#if REGEX
#include "tests_helpers.h"
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

static void ovh_regex_simple_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;
  ovh_regex_t* regex = ovh_regex_new("(.*)(hello)+");

  int result = ovh_regex_match(regex, "This should match... hello");
  assert_int_equal(1, result);
  result = ovh_regex_match(regex, "This should not match...");
  assert_int_equal(0, result);
  ovh_regex_free(regex);

  regex = ovh_regex_new("/phish/(.*)make_7\\.html");
  result = ovh_regex_match(regex, "/phish/dfdfdfdfdfmake_7.html");
  assert_int_equal(1, result);
  result = ovh_regex_match(regex, "/phish/dfdfdfdfdfmake_7.html?more=yes");
  assert_int_equal(1, result);

  ovh_regex_free(regex);

  CHECK_ZERO_MEMORY_ALLOCATED;
}

static void ovh_regex_clone_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;

  ovh_regex_t* orig = ovh_regex_new("(.*)(hello)+");
  ovh_regex_t* regex = ovh_regex_clone(orig);

  int result = ovh_regex_match(regex, "This should match... hello");
  assert_int_equal(1, result);
  result = ovh_regex_match(regex, "This should not match...");
  assert_int_equal(0, result);
  ovh_regex_free(regex);

  regex = ovh_regex_new("/phish/(.*)make_7\\.html");
  result = ovh_regex_match(regex, "/phish/dfdfdfdfdfmake_7.html");
  assert_int_equal(1, result);
  result = ovh_regex_match(regex, "/phish/dfdfdfdfdfmake_7.html?more=yes");
  assert_int_equal(1, result);

  ovh_regex_free(regex);
  ovh_regex_free(orig);

  CHECK_ZERO_MEMORY_ALLOCATED;
}


static const struct CMUnitTest tests[] = {
  cmocka_unit_test(ovh_regex_simple_test),
  cmocka_unit_test(ovh_regex_clone_test),
};

SUPPRESS_UNUSED_WARN(ovh_regex_simple_test);
SUPPRESS_UNUSED_WARN(ovh_regex_clone_test);

test_helper_group(tests, suite_setup, suite_teardown);

#endif