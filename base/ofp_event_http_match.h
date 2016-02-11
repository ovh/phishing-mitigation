#ifndef __OFP_EVENT_HTTP_MATCH_H__
#define __OFP_EVENT_HTTP_MATCH_H__


#include "ovh_event_queue.h"
#include "ofp_http.h"
#include "ofp_init.h"

#define EVENT_HTTP_MATCH_LOG_DATA_SIZE 1024
#define EVENT_HTTP_MATCH_LOG_LINE_SIZE (4*1024)
#define EVENT_HTTP_MATCH_MEMPOOL_SIZE (16*1024)

typedef struct ofp_event_http_match_entry_s
{
  char log[EVENT_HTTP_MATCH_LOG_LINE_SIZE];
  uint8_t data[EVENT_HTTP_MATCH_LOG_DATA_SIZE];
  uint32_t data_len;
  struct ofp_event_http_match_entry_s *mp_next; // For memory pool
  struct ofp_event_http_match_entry_s *next; // For queue
} ofp_event_http_match_entry_t;


extern ovh_event_queue_t event_queue_http_match;

extern const char* EVENT_HTTP_REASON_UNKOWN;
extern const char* EVENT_HTTP_REASON_ERROR;
extern const char* EVENT_HTTP_REASON_SUCCESS;

typedef enum
{
  HttpMatchActionPASS = 1,
  HttpMatchActionRST = 2,
} http_match_action_t;

extern const char* EVENT_HTTP_MATCH_ACTION_RST;
extern const char* EVENT_HTTP_MATCH_ACTION_PASS;

static inline const char* http_match_action_to_str(http_match_action_t action)
{
  switch(action)
  {
    case HttpMatchActionPASS:
      return EVENT_HTTP_MATCH_ACTION_PASS;
    case HttpMatchActionRST:
      return EVENT_HTTP_MATCH_ACTION_RST;
    default:
      OVH_ASSERT(TODO);
      return EVENT_HTTP_REASON_UNKOWN;
  }
}


extern const char* EVENT_HTTP_MATCH_REASON_START_WITH;
extern const char* EVENT_HTTP_MATCH_REASON_REGEX;
extern const char* EVENT_HTTP_MATCH_REASON_HOST_MISMATCH;
extern const char* EVENT_HTTP_MATCH_REASON_URL_MISMATCH;
extern const char* EVENT_HTTP_MATCH_REASON_IP_MISMATCH;
extern const char* EVENT_HTTP_MATCH_REASON_PORT_MISMATCH;
extern const char* EVENT_HTTP_MATCH_REASON_BAD_METHOD;
extern const char* EVENT_HTTP_MATCH_REASON_NO_METHOD;
extern const char* EVENT_HTTP_MATCH_REASON_PASS_THROUGH;


static inline const char* http_match_result_to_str(http_match_result_t result)
{
  switch(result)
  {
    case HttpMatchUrlNotInList:
      return EVENT_HTTP_MATCH_REASON_URL_MISMATCH;
    case HttpMatchBadHostname:
      return EVENT_HTTP_MATCH_REASON_HOST_MISMATCH;
    case HttpMatchBadMethod:
      return EVENT_HTTP_MATCH_REASON_BAD_METHOD;
    case HttpMatchNoMethod:
      return EVENT_HTTP_MATCH_REASON_NO_METHOD;
    case HttpMatchStartWith:
      return EVENT_HTTP_MATCH_REASON_START_WITH;
    case HttpMatchRegex:
      return EVENT_HTTP_MATCH_REASON_REGEX;
    case HttpMatchError:
      return EVENT_HTTP_REASON_ERROR;
    default:
      OVH_ASSERT(TODO);
      return EVENT_HTTP_REASON_UNKOWN;
  }
}

extern const char* EVENT_HTTP_CHECK_REASON_IGNORED_METHOD;
extern const char* EVENT_HTTP_CHECK_REASON_NO_METHOD;

static inline const char* http_check_result_to_str(http_parse_result_t result)
{
  switch(result)
  {
    case HttpCheckIgnoredMethod:
      return EVENT_HTTP_CHECK_REASON_IGNORED_METHOD;
    case HttpCheckNoMethod:
      return EVENT_HTTP_CHECK_REASON_NO_METHOD;
    case HttpCheckError:
      return EVENT_HTTP_REASON_ERROR;
    case HttpCheckSuccess:
      return EVENT_HTTP_REASON_SUCCESS;
    default:
      OVH_ASSERT(TODO);
      return EVENT_HTTP_REASON_UNKOWN;
  }
}

extern const char* EVENT_HTTP_PARSE_REASON_NO_URI;
extern const char* EVENT_HTTP_PARSE_REASON_NO_METHOD;
extern const char* EVENT_HTTP_PARSE_REASON_DATA_TOO_SMALL;

static inline const char* http_parse_result_to_str(http_parse_result_t result)
{
  switch(result)
  {
    case HttpParseNoURI:
      return EVENT_HTTP_PARSE_REASON_NO_URI;
    case HttpParseNoMethod:
      return EVENT_HTTP_PARSE_REASON_NO_METHOD;
    case HttpParseDataTooSmall:
      return EVENT_HTTP_PARSE_REASON_DATA_TOO_SMALL;
    case HttpParseError:
      return EVENT_HTTP_REASON_ERROR;
    case HttpParseSuccess:
      return EVENT_HTTP_REASON_SUCCESS;
    default:
      OVH_ASSERT(TODO);
      return EVENT_HTTP_REASON_UNKOWN;
  }
}



void ofp_event_http_match_init(size_t mempool_size);
void ofp_event_http_match_close();

void ofp_event_http_match_log(FILE* file);

static inline void ofp_event_http_match_add(int rank, http_match_action_t actionId, const char* reason, ofp_http_request_description_t* desc, const char* pattern, uint8_t* l3Data, uint32_t l3DataLength, uint32_t ipSrcInt, uint32_t ipDstInt, uint16_t portSrc, uint16_t portDst)
{
  const char* action = http_match_action_to_str(actionId);

  ofp_event_http_match_entry_t* entry = NULL;
  OVH_EVENT_QUEUE_GET_FREE(&event_queue_http_match, entry);
  if (entry == NULL) return;

  //clean entry
  entry->log[0] = '\0';
  entry->data_len = 0;
  entry->data[0] = '\0';

  //if desc is null, replace by default value
  ofp_http_request_description_t emptyDesc = {{0}};
  if(desc == NULL) desc = &emptyDesc;

  ip_address_t ipDst = ip_to_struct(ipDstInt);
  ip_address_t ipSrc = ip_to_struct(ipSrcInt);

  if(actionId == HttpMatchActionPASS)
  {
    snprintf(entry->log, EVENT_HTTP_MATCH_LOG_LINE_SIZE,
"exampleSDID@32473 eventSource=\"tilera-phishing\" eventID=\"1\" "\
"ovhTimestamp=\"%lu\" ovhTilera=\"%s\" ovhFlag=\"antiphishing\" "\
"ovhIpDst=\"%d.%d.%d.%d\" "\
"ovhAction=\"%s\" ovhReason=\"%s\" ovhMethod=\"%.*s\" "\
"ovhUserAgent=\"%.*s\" ovhPacketSize=\"%d\" "\
"ovhPattern=\"%.*s%s\"",
      OVH_CUR_TIME_MS, ofp_host_name,
      ipDst.a, ipDst.b, ipDst.c, ipDst.d,
      action, reason,
      desc->method.length, desc->method.data,
      desc->userAgent.length, desc->userAgent.data,
      l3DataLength,
      pattern == NULL ? 0 : desc->host.length, desc->host.data, pattern == NULL ? "" : pattern //concat host&pattern
    );
  }
  else if(actionId == HttpMatchActionRST)
  {
    snprintf(entry->log, EVENT_HTTP_MATCH_LOG_LINE_SIZE,
"exampleSDID@32473 eventSource=\"tilera-phishing\" eventID=\"1\" "\
"ovhTimestamp=\"%lu\" ovhTilera=\"%s\" ovhFlag=\"antiphishing\" "\
"ovhIpSrc=\"%d.%d.%d.xxx\" ovhIpDst=\"%d.%d.%d.%d\" "\
"ovhAction=\"%s\" ovhReason=\"%s\" ovhMethod=\"%.*s\" "\
"ovhUserAgent=\"%.*s\" ovhPacketSize=\"%d\" "\
"ovhPattern=\"%.*s%s\" "\
"ovhUrl=\"%.*s%.*s\" ovhHostname=\"%.*s\" ovhPath=\"%.*s\"",
      OVH_CUR_TIME_MS, ofp_host_name,
      ipSrc.a, ipSrc.b, ipSrc.c,
      ipDst.a, ipDst.b, ipDst.c, ipDst.d,
      action, reason,
      desc->method.length, desc->method.data,
      desc->userAgent.length, desc->userAgent.data,
      l3DataLength,
      pattern == NULL ? 0 : desc->host.length, desc->host.data, pattern == NULL ? "" : pattern,
      desc->host.length, desc->host.data,
      desc->uri.length, desc->uri.data,
      desc->host.length, desc->host.data,
      desc->uri.length, desc->uri.data
    );

    if(l3Data != NULL && l3DataLength > 0)
    {
      //copy at most EVENT_HTTP_MATCH_LOG_DATA_SIZE bytes
      //and replace special char with '.'
      entry->data_len = OVH_MIN(l3DataLength, EVENT_HTTP_MATCH_LOG_DATA_SIZE);
      for (int i = 0; i < entry->data_len; ++i)
      {
        if(l3Data[i] < 32)
        {
          entry->data[i] = '.';
        }
        if(l3Data[i] > 125)
        {
          entry->data[i] = '.';
        }
        else
        {
          entry->data[i] = l3Data[i];
        }
      }
    }

  }
  else
  {
    OVH_ASSERT(TODO);
  }

  //Replace "[,]" with "{,}", since ']' make syslog parser fail
  for (int i = 0; i < EVENT_HTTP_MATCH_LOG_LINE_SIZE; ++i)
  {
    if(entry->log[i] == '[')
    {
      entry->log[i] = '{';
    }
    else if(entry->log[i] == ']')
    {
      entry->log[i] = '}';
    }
    else if(entry->log[i] == '\0')
    {
      break;
    }
  }

  OVH_EVENT_QUEUE_PUSH(&event_queue_http_match, entry, ofp_event_http_match_entry_t);
}

#endif //__OFP_EVENT_HTTP_MATCH_H__