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
#include "ofp_defines.h"
#include "ofp_event_http_match.h"

ovh_event_queue_t event_queue_http_match;

const char* EVENT_HTTP_REASON_UNKOWN = "unknown";
const char* EVENT_HTTP_REASON_ERROR = "error";
const char* EVENT_HTTP_REASON_SUCCESS = "success";

const char* EVENT_HTTP_MATCH_ACTION_RST = "RST";
const char* EVENT_HTTP_MATCH_ACTION_PASS = "PASS";

const char* EVENT_HTTP_MATCH_REASON_START_WITH = "Match start with";
const char* EVENT_HTTP_MATCH_REASON_REGEX = "Match Regex";
const char* EVENT_HTTP_MATCH_REASON_HOST_MISMATCH = "Host not in list";
const char* EVENT_HTTP_MATCH_REASON_URL_MISMATCH = "URL not in list";
const char* EVENT_HTTP_MATCH_REASON_IP_MISMATCH = "IP mismatch";
const char* EVENT_HTTP_MATCH_REASON_PORT_MISMATCH = "Port mismatch";
const char* EVENT_HTTP_MATCH_REASON_BAD_METHOD = "Bad method";
const char* EVENT_HTTP_MATCH_REASON_NO_METHOD = "No method";
const char* EVENT_HTTP_MATCH_REASON_PASS_THROUGH = "Pass through";

const char* EVENT_HTTP_CHECK_REASON_IGNORED_METHOD = "Ignored method";
const char* EVENT_HTTP_CHECK_REASON_NO_METHOD = "No method";

const char* EVENT_HTTP_PARSE_REASON_NO_URI = "No URI found";
const char* EVENT_HTTP_PARSE_REASON_NO_METHOD = "No method found";
const char* EVENT_HTTP_PARSE_REASON_DATA_TOO_SMALL = "Data too small";


void ofp_event_http_match_init(size_t mempool_size)
{
  if(mempool_size == 0)
  {
    mempool_size = EVENT_HTTP_MATCH_MEMPOOL_SIZE;
  }
  OVH_EVENT_QUEUE_INIT(&event_queue_http_match, mempool_size, ofp_event_http_match_entry_t);
}

void ofp_event_http_match_close()
{
  OVH_EVENT_QUEUE_DISCARD(&event_queue_http_match);
}


void ofp_event_http_match_log(FILE* file)
{
  OVH_ASSERT(file != NULL);
  ovh_event_queue_t queue;
  OVH_EVENT_QUEUE_COPY_AND_RESET(&event_queue_http_match, &queue);
  if (queue.size > 0)
  {
    ofp_event_http_match_entry_t* entry = queue.first;

    while (entry != NULL)
    {
      fprintf(file, "[%s] %.*s\n", entry->log, entry->data_len, entry->data);

      OVH_EVENT_QUEUE_FREE_GET_NEXT(&queue, entry, ofp_event_http_match_entry_t);
    }
  }
}