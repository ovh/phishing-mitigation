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
#include "ofp_socket.h"
#include "ofp_init.h"
#include "ofp_socket.h"
#include "ofp_workers.h"
#include "ofp_socket_message_cb.h"
#include "ofp_config_ip.h"

#if SOCKET
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

static int ofp_socket_test_message_cb(int socket, char* data)
{
  printf("test received : '%s'\n", data);
  int res = ofp_socket_message_cb(socket, data);
  return res;
}

static int ofp_socket_test_error_cb(int socket)
{
  return 0;
}

static void ofp_socket_test(void** state)
{
  ofp_phish_desc_hash_table_locked_t descsLocked = ofp_phish_desc_ht_lock(config_desc_hash);
  int result = config_ip_desc_add_file(descsLocked, "../conf/ip.conf");
  assert_int_equal(1, result);
  ofp_phish_desc_ht_unlock(descsLocked);

  socket_start(ofp_socket_test_message_cb, ofp_socket_test_error_cb);

  while(!prgm_exit_requested)
  {
    break;
  }

  descsLocked = ofp_phish_desc_ht_lock(config_desc_hash);
  ofp_phish_desc_ht_free_elements(descsLocked);
  ofp_phish_desc_ht_unlock(descsLocked);
  socket_stop();

}


static const struct CMUnitTest tests[] = {
  cmocka_unit_test(ofp_socket_test),
};

test_helper_group(tests, suite_setup, suite_teardown);

SUPPRESS_UNUSED_WARN(ofp_socket_test);

#endif