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
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include "tests_helpers.h"
#include "ofp_socket.h"
#include "ofp_init.h"
#include "ofp_socket.h"
#include "ofp_workers.h"
#include "ofp_socket_message_cb.h"
#include "ofp_config_ip.h"
#include "ofp_http.h"
#include "ofp_event_http_match.h"

static int suite_setup(void **state) {
  int workerCount = 29;
  ofp_init(workerCount, 3);
  ofp_init_alloc_shared(NULL);
  return 0;
}

static int suite_teardown(void **state) {
  ofp_free_shared();
  ofp_close();
  return 0;
}

static void* event_queue_run(void* arg)
{
  int* rankPtr = arg;
  int rank = *rankPtr;

  ofp_http_request_description_t desc;
  inplace_string_set(&desc.method, "GET");
  inplace_string_set(&desc.host, "example.com:1234");
  inplace_string_set(&desc.uri, "/index.html");

  do
  {
    for (int i = 0; i < 250; ++i)
    {
      ofp_event_http_match_add(rank, HttpMatchActionPASS, EVENT_HTTP_PARSE_REASON_NO_URI, &desc, "/index.html", httpGetTcpData, httpGetTcpDataLength, 1, 2, 3, 4);
    }

    //int r = rand() % (10 * 1000);
    usleep(10*1000);
    //sleep(1);

  } while(1);


  return NULL;
}

static void ofp_event_queue_test(void** state)
{
  srand(1234587);

  int* rankPtr = (int *)OVH_MALLOC(sizeof(int));
  int rank = 0;
  *rankPtr = rank;

  for (int i = 0; i < 0; ++i)
  {
    pthread_t newThread;
    if (pthread_create(&newThread, NULL, event_queue_run, rankPtr))
    {
      TMC_TASK_DIE("pthread_create failed for socket_run.");
    }
  }

  int mem_used = 0;
  int mem_allocated = 0;
  int mp_usage = 0;
  int callCount = 0;
  do
  {
    OVH_MEMPOOL_PRINT_USAGE(stdout, event_queue_http_match.mempool, mem_used, mem_allocated, mp_usage);
    printf("mp_usage = %d%%\n", mp_usage);

    OVH_EVENT_QUEUE_PRINT_USAGE(stdout, event_queue_http_match);
    ofp_event_http_match_log(stdout);

    OVH_ASSERT(mp_usage <= 100);
    printf("callCount=%d sleeping...\n", callCount);

    int r = rand() % 10;
    usleep(r*1000);

    callCount++;
    break;
  } while(1);

  OVH_FREE(rankPtr);

}


static const struct CMUnitTest tests[] = {
  cmocka_unit_test(ofp_event_queue_test),
};

test_helper_group(tests, suite_setup, suite_teardown);

SUPPRESS_UNUSED_WARN(ofp_event_queue_test);

