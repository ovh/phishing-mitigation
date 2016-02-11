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
#include "tests_helpers.h"
#include "ofp_init.h"
#include "ofp_URI_list.h"


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

typedef struct
{
  ovh_mempool* listPool;
  ovh_mempool* entryPool;
  ofp_uri_list_t* list;
} data_t;

static int test_setup(void **state) {
  data_t* data = (data_t *)OVH_MALLOC(sizeof(data_t));

  data->listPool = ofp_uri_list_new_pool(100, NULL);
  data->entryPool = ofp_uri_list_entry_new_pool(100, NULL);
  data->list = ofp_uri_list_new_from(data->listPool, data->entryPool);

  *state = data;
  return 0;
}

static int test_teardown(void **state) {
  data_t* data = (data_t* )*state;

  OVH_MEMPOOL_DISCARD_SHARED(data->listPool);
  OVH_MEMPOOL_DISCARD_SHARED(data->entryPool);
  OVH_FREE(data);
  return 0;
}

static void linked_list_init_test(void** state)
{
  data_t* data = (data_t* )*state;
  ofp_uri_list_t* list = data->list;

  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));

  assert_null(list->head);
  assert_null(list->tail);
  assert_int_equal(0, list->count);

  ofp_uri_list_free_elements(list);
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));
}

static void linked_list_add_test(void** state)
{
  data_t* data = (data_t* )*state;
  ofp_uri_list_t* list = data->list;

  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));

  ofp_uri_list_entry_t* entry = ofp_uri_list_entry_new(list);
  assert_non_null(entry);
  assert_null(entry->next);
  assert_null(entry->uri);

  assert_ptr_equal(list->head, entry);
  assert_ptr_equal(list->tail, entry);
  assert_int_equal(1, list->count);

  assert_int_equal(sizeof(ofp_uri_list_entry_t), OVH_MEMPOOL_STATS_USED(*list->entryPool));

  entry = ofp_uri_list_entry_new(list);
  assert_non_null(entry);
  assert_ptr_equal(list->tail, entry);

  entry = ofp_uri_list_entry_new(list);
  assert_non_null(entry);
  assert_ptr_equal(list->tail, entry);

  assert_int_equal(3, list->count);
  assert_int_equal(3 * sizeof(ofp_uri_list_entry_t), OVH_MEMPOOL_STATS_USED(*list->entryPool));


  ofp_uri_list_free_elements(list);
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));
}

static void linked_list_add_values_test(void** state)
{
  data_t* data = (data_t* )*state;
  ofp_uri_list_t* list = data->list;

  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));

  ofp_uri_list_entry_t* entry = ofp_uri_list_entry_add_uri(list, strdup("value1"));
  assert_non_null(entry);
  assert_non_null(entry->uri);
  assert_string_equal(entry->uri, "value1");

  entry = ofp_uri_list_entry_add_uri(list, strdup("value2"));
  assert_non_null(entry);
  assert_non_null(entry->uri);
  assert_string_equal(entry->uri, "value2");

  entry = ofp_uri_list_entry_add_uri(list, strdup("value3"));
  assert_non_null(entry);
  assert_non_null(entry->uri);
  assert_string_equal(entry->uri, "value3");

  //check data order
  entry = list->head;
  int index = 1;
  char str[256];
  while(entry)
  {
    assert_non_null(entry->uri);
    sprintf(str, "value%d", index);
    assert_string_equal(entry->uri, str);
    entry = entry->next;
    index++;
  }

  ofp_uri_list_free_elements(list);
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));
}


static void linked_list_free_elements_test(void** state)
{
  data_t* data = (data_t* )*state;
  ofp_uri_list_t* list = data->list;

  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));

  ofp_uri_list_entry_new(list);
  ofp_uri_list_entry_new(list);
  ofp_uri_list_entry_new(list);

  assert_int_equal(3, list->count);
  assert_int_equal(3 * sizeof(ofp_uri_list_entry_t), OVH_MEMPOOL_STATS_USED(*list->entryPool));

  ofp_uri_list_free_elements(list);
  assert_null(list->head);
  assert_null(list->tail);
  assert_int_equal(0, list->count);
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));

  ofp_uri_list_free_elements(list);
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));
}

static void linked_list_clone_test(void** state)
{
  data_t* data = (data_t* )*state;
  ofp_uri_list_t* list = data->list;

  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*ofp_uri_list_pool));
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*ofp_uri_list_entry_pool));

  ofp_uri_list_entry_t* entry = ofp_uri_list_entry_add_uri(list, strdup("value1"));
  entry = ofp_uri_list_entry_add_uri(list, strdup("value2"));
  entry = ofp_uri_list_entry_add_uri(list, strdup("value3"));

  ofp_uri_list_t* list_clone = ofp_uri_list_clone(list);

  assert_int_equal(list->count, list_clone->count);
  //check data order
  entry = list_clone->head;
  int index = 1;
  char str[256];
  while(entry)
  {
    assert_non_null(entry->uri);
    sprintf(str, "value%d", index);
    assert_string_equal(entry->uri, str);
    entry = entry->next;
    index++;
  }


  ofp_uri_list_free_elements(list);
  ofp_uri_list_free(list_clone);

  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list->entryPool));
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*list_clone->entryPool));

  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*ofp_uri_list_pool));
  assert_int_equal(0, OVH_MEMPOOL_STATS_USED(*ofp_uri_list_entry_pool));
}

static const struct CMUnitTest tests[] = {
  cmocka_unit_test_setup_teardown(linked_list_init_test, test_setup, test_teardown),
  cmocka_unit_test_setup_teardown(linked_list_add_test, test_setup, test_teardown),
  cmocka_unit_test_setup_teardown(linked_list_add_values_test, test_setup, test_teardown),
  cmocka_unit_test_setup_teardown(linked_list_free_elements_test, test_setup, test_teardown),
  cmocka_unit_test_setup_teardown(linked_list_clone_test, test_setup, test_teardown),
};

test_helper_group(tests, suite_setup, suite_teardown);

SUPPRESS_UNUSED_WARN(test_setup);
SUPPRESS_UNUSED_WARN(test_teardown);
SUPPRESS_UNUSED_WARN(linked_list_init_test);
SUPPRESS_UNUSED_WARN(linked_list_add_test);
SUPPRESS_UNUSED_WARN(linked_list_add_values_test);
SUPPRESS_UNUSED_WARN(linked_list_free_elements_test);
SUPPRESS_UNUSED_WARN(linked_list_clone_test);
