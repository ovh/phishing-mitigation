#ifndef __OFP_HTTP_H__
#define __OFP_HTTP_H__

#include "ofp.h"
#include "ofp_errors.h"
#include "ofp_URI_list.h"

typedef enum
{
  HttpMatchUrlNotInList = -4,
  HttpMatchBadHostname = -3,
  HttpMatchBadMethod = -2,
  HttpMatchNoMethod = -1,
  HttpMatchError = 0,
  HttpMatchStartWith = 1,
  HttpMatchRegex = 2,
} http_match_result_t;

typedef enum
{
  HttpParseNoURI = -3,
  HttpParseNoMethod = -2,
  HttpParseDataTooSmall = -1,
  HttpParseError = 0,
  HttpParseSuccess = 1,
} http_parse_result_t;

typedef enum
{
  HttpCheckIgnoredMethod = -2,
  HttpCheckNoMethod = -1,
  HttpCheckError = 0,
  HttpCheckSuccess = 1,
} http_check_result_t;

//=======================================================================================================
// Describe a parsed http request header
// - Method : http header method
// - Host (can be null) : if present (http 1.1) extracted Host from http request
// - URI : method URI
//=======================================================================================================
typedef struct _http_request_description
{
  inplace_string_t method;
  inplace_string_t host;
  inplace_string_t uri;
  inplace_string_t userAgent;
} ofp_http_request_description_t;

static inline int http_has_custom_header_field(uint8_t *l3Data, uint32_t l3DataLength,
                                               const char *header_field, int header_field_len)
{
  char *data = (char *)l3Data;
  uint32_t dataLen = l3DataLength;

  // Go to next CRLF ( in http1.1, Request-Line MUST be followed by CRLF, in http 1.0 no host will
  // be found )
  char *crlf = strNextCRLF(data, dataLen);

  while (crlf != NULL)
  {
    data = crlf + 2; // skip CRLF
    // recompute remaining dataLen
    int offset = data - (char *)l3Data;
    dataLen = l3DataLength - offset;
    if (dataLen <= 0)
      break; // not enough data remaining

    if (OVH_STR_START_WITH_2(data, dataLen, header_field, header_field_len))
    {
      return 1;
    }

    // next CRLF
    crlf = strNextCRLF(data, dataLen);
  };

  return 0;
}

//=======================================================================================================
// Parse http header from a L3 Data block
// Extract :
// - Method
// - Host (null if http 1.0)
// - URI
// return 1 if this is a http packet and we successfully extracted Method and URI
// Return 0 if fail to extract expected data
//=======================================================================================================
static inline http_parse_result_t http_parse(uint8_t *l3Data, uint32_t l3DataLength,
                                             ofp_http_request_description_t *result)
{
  static const char GET_METHOD[] = "GET ";
  static const int GET_METHOD_LEN = sizeof(GET_METHOD) - 1;

  static const char HOST_FIELD[] = "Host: ";
  static const int HOST_FIELD_LEN = sizeof(HOST_FIELD) - 1;

  static const char USERAGENT_FIELD[] = "User-Agent: ";
  static const int USERAGENT_FIELD_LEN = sizeof(USERAGENT_FIELD) - 1;

  char *data = (char *)l3Data;
  uint32_t dataLen = l3DataLength;

  // The Request-Line begins with a method token, followed by the Request-URI and the protocol
  // version, and ending with CRLF.
  // The elements are separated by SP characters. No CR or LF is allowed except in the final CRLF
  // sequence.

  //=========================
  // Extract METHOD from data
  //=========================
  int minL3DataLength =
      GET_METHOD_LEN +
      2; // data should at least contains method + crlf , min method size is GET method
  if (dataLen < minL3DataLength)
  {
    PRINT_D5("dataLen tool small\n");
    return HttpParseDataTooSmall; // too short, cannot be a valid request
  }

  // we expect method, followed by SP char
  char *methodEnd = memchr(data, ' ', dataLen);
  if (methodEnd == NULL)
  {
    PRINT_D5("method not found\n");
    return HttpParseNoMethod;
  }
  result->method.data = data;
  int methodLen = methodEnd - data;
  result->method.length = methodLen;
  PRINT_D5("method : '%.*s'\n", methodLen, data);

  //======================
  // Extract URI from data
  //======================

  // we just keep a pointer and length to URI so we do not do any allocation
  int methodOffset = methodLen + 1; // skip method and SP char
  char *uri = data + methodOffset;
  int uriLength = 0;
  for (int i = methodOffset; i < dataLen - 1; ++i) // data always finish by crlf, so we can check
                                                   // n-1 chars and  safely do data[i+1] inside the
                                                   // loop
  {
    if (data[i] == ' ' || // http1.1 : uri is followed by SP char
        (data[i] == '\r' && data[i + 1] == '\n') // http1.0 or 0.9 : uri is followed by CRLF
        )
    {
      uriLength = i - methodOffset;
      break;
    }
  }

  if (uriLength <= 0)
  {
    PRINT_D5("URI not found\n");
    return HttpParseNoURI; // No separator found
  }

  PRINT_D5("URI : '%.*s'\n", uriLength, uri);
  result->uri.data = uri;
  result->uri.length = uriLength;

  //======================
  // Extract Fields from data
  // Host
  // User-Agent
  //======================

  // HTTP 1.1 only, search for "Host: hostName"
  char *hostName = NULL;
  int hostNameLength = 0;

  char *userAgent = NULL;
  int userAgentLength = 0;

  // Go to next CRLF ( in http1.1, Request-Line MUST be followed by CRLF, in http 1.0 no host will
  // be found )
  char *crlf = strNextCRLF(data, dataLen);

  while (crlf != NULL && (hostName == NULL || userAgent == NULL))
  {
    data = crlf + 2; // skip CRLF
    // recompute remaining dataLen
    int offset = data - (char *)l3Data;
    dataLen = l3DataLength - offset;
    if (dataLen <= 0)
      break; // not enough data remaining

    if (OVH_STR_START_WITH_2(data, dataLen, HOST_FIELD, HOST_FIELD_LEN))
    {
      char *hostNameEnd = strNextCRLF(data, dataLen);
      if (hostNameEnd != NULL)
      {
        hostName = data + HOST_FIELD_LEN;
        hostNameLength = hostNameEnd - hostName;
      }
    }

    if (OVH_STR_START_WITH_2(data, dataLen, USERAGENT_FIELD, USERAGENT_FIELD_LEN))
    {
      char *userAgentEnd = strNextCRLF(data, dataLen);
      if (userAgentEnd != NULL)
      {
        userAgent = data + USERAGENT_FIELD_LEN;
        userAgentLength = userAgentEnd - userAgent;
      }
    }

    // next CRLF
    crlf = strNextCRLF(data, dataLen);
  };

  result->host.data = NULL;
  result->host.length = 0;

  if (hostName != NULL && hostNameLength > 0)
  {
    PRINT_D5("HOST_FIELD : '%.*s'\n", hostNameLength, hostName);

    result->host.data = hostName;
    result->host.length = hostNameLength;
  }
  else
  {
    PRINT_D5("HOST_FIELD not found\n");
  }

  if (userAgent != NULL && userAgentLength > 0)
  {
    PRINT_D5("UserAgent  : '%.*s'\n", userAgentLength, userAgent);

    result->userAgent.data = userAgent;
    result->userAgent.length = userAgentLength;
  }

  return HttpParseSuccess;
}

//=======================================================================================================
// Check given Http Request description match :
// - targetHostName if not null
// - any one of URIs
// return 1 if match
// Return 0 if no match
//=======================================================================================================
static inline http_match_result_t http_match(ofp_http_request_description_t *desc,
                                             char *targetHostName, ofp_uri_list_t *uriList,
                                             ofp_uri_list_entry_t **matchEntry)
{
  static const char WWWDOT[] = "www.";
  static const int WWWDOT_LEN = sizeof(WWWDOT) - 1;
  *matchEntry = NULL;

  if (desc->host.data != NULL && desc->host.length > 0)
  {
    if (targetHostName != NULL) // do we need to check http host field ?
    {
      char *descHostData = desc->host.data;
      int descHostLength = desc->host.length;

      if (OVH_STR_START_WITH_2(descHostData, descHostLength, WWWDOT,
                               WWWDOT_LEN)) // host start with "wwww."
      {
        descHostData += WWWDOT_LEN; // skip it
        descHostLength -= WWWDOT_LEN; // update new len
        if (descHostLength <= 0)
        {
          PRINT_ERR("request.Host is invalid : '%.*s'\n", desc->host.length, desc->host.data);
          return HttpMatchError;
        }
      }

      if (!OVH_STR_EQUAL(descHostData, descHostLength, targetHostName))
      {
        PRINT_D5("request.Host '%.*s' do not match target : %s\n", desc->host.length,
                 desc->host.data, targetHostName);
        return HttpMatchBadHostname;
      }
      PRINT_D5("request.Host match target : %s\n", targetHostName);
    }
  }
  else
  {
    PRINT_D5("request.Host not present (HTTP 1.0 ?)\n");
  }

  // We successfully found an URI
  // Check it against all target uris
  ofp_uri_list_entry_t *currentURI = uriList->head;
  while (currentURI != NULL)
  {
    char *targetURI = currentURI->uri;
    if (targetURI != NULL && OVH_STR_START_WITH(desc->uri.data, desc->uri.length, targetURI))
    {
      PRINT_D2("[MATCH] '%.*s' request.URI '%.*s' is matching target : '%s' '%s'\n",
               desc->host.length, desc->host.data, desc->uri.length, desc->uri.data,
               targetHostName != NULL ? targetHostName : "no host", targetURI);
      *matchEntry = currentURI;
      return HttpMatchStartWith; // match !!
    }

#if REGEX
    ovh_regex_t *regex = currentURI->regex;
    if (regex != NULL && ovh_regex_match2(regex, desc->uri.data, desc->uri.length))
    {
      PRINT_D2("[MATCH] '%.*s' request.URI '%.*s' is matching target regex : '%s' '%s'\n",
               desc->host.length, desc->host.data, desc->uri.length, desc->uri.data,
               targetHostName != NULL ? targetHostName : "no host", regex->pattern);
      *matchEntry = currentURI;
      return HttpMatchRegex; // match !!
    }
#endif

    currentURI = currentURI->next;
  }

  PRINT_D5("request.URI '%.*s' do not match any target URIs\n", desc->uri.length, desc->uri.data);

  // Nothing found
  return HttpMatchUrlNotInList;
}

static inline http_check_result_t http_check(ofp_http_request_description_t *desc)
{
  static const char GET_METHOD[] = "GET";
  static const int GET_METHOD_LEN = sizeof(GET_METHOD) - 1;

  if (desc->method.data == NULL || desc->method.length == 0)
  {
    PRINT_D5("request.Method not present\n");
    return HttpCheckNoMethod;
  }

  // currently, we manage GET method only
  if (strncmp(desc->method.data, GET_METHOD, GET_METHOD_LEN) != 0)
  {
    PRINT_D5("request.Method '%.*s' do not match '%s'\n", desc->method.length, desc->method.data,
             GET_METHOD);
    return HttpCheckIgnoredMethod;
  }

  return HttpCheckSuccess;
}

//=======================================================================================================
// Nomalize Http request host field by removing "www." prefix
// return 1 if ok
// Return 0 if fail
//=======================================================================================================
static inline int http_strip_www(ofp_http_request_description_t *desc)
{
  static const char WWWDOT[] = "www.";
  static const int WWWDOT_LEN = sizeof(WWWDOT) - 1;

  char *descHostData = desc->host.data;
  int descHostLength = desc->host.length;

  if (OVH_STR_START_WITH_2(descHostData, descHostLength, WWWDOT,
                           WWWDOT_LEN)) // host start with "wwww."
  {
    descHostData += WWWDOT_LEN; // skip it
    descHostLength -= WWWDOT_LEN; // update new len
    if (descHostLength <= 0)
    {
      PRINT_ERR("request.Host is invalid : '%.*s'\n", desc->host.length, desc->host.data);
      return 0;
    }

    desc->host.data = descHostData;
    desc->host.length = descHostLength;
  }

  return 1;
}

#endif //__OFP_HTTP_H__
