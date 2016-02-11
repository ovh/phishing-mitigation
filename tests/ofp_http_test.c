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
#include "ofp_http.h"
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

static void ofp_http_get_parse_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;

  uint8_t* tcpData = (uint8_t*)httpGetTcpData;
  uint32_t tcpDataLength = httpGetTcpDataLength;

  ofp_http_request_description_t desc;
  int l3offset = 0x34;
  int l3Length = tcpDataLength - l3offset;
  uint8_t* l3Data = &tcpData[l3offset];
  http_parse_result_t result = http_parse(l3Data, l3Length, &desc);
  assert_int_equal(HttpParseSuccess, result);
  assert_memory_equal("GET", desc.method.data, desc.method.length);
  assert_memory_equal("www.example.com", desc.host.data, desc.host.length);
  assert_memory_equal("/index.html?toto=123", desc.uri.data, desc.uri.length);

  CHECK_ZERO_MEMORY_ALLOCATED;
}

static void ofp_http_put_parse_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;

  uint8_t* tcpData = (uint8_t*)httpPutTcpData;
  uint32_t tcpDataLength = httpPutTcpDataLength;

  ofp_http_request_description_t desc;
  int l3offset = 0x34;
  int l3Length = tcpDataLength - l3offset;
  uint8_t* l3Data = &tcpData[l3offset];
  http_parse_result_t result = http_parse(l3Data, l3Length, &desc);
  assert_int_equal(HttpParseSuccess, result);
  assert_memory_equal("PUT", desc.method.data, desc.method.length);
  assert_memory_equal("www.example.com", desc.host.data, desc.host.length);
  assert_memory_equal("/index.html?toto=123", desc.uri.data, desc.uri.length);
  printf("(%.*s)\n", desc.userAgent.length, desc.userAgent.data);
  assert_memory_equal("Wget/1.13.4 (linux-gnu)", desc.userAgent.data, desc.userAgent.length);

  CHECK_ZERO_MEMORY_ALLOCATED;
}


static void ofp_http_strip_www_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;

  ofp_http_request_description_t desc;
  inplace_string_set(&desc.method, "GET");
  inplace_string_set(&desc.host, "www.example.com");
  inplace_string_set(&desc.uri, "/index.html");

  int result = http_strip_www(&desc);
  assert_int_equal(1, result);
  assert_int_equal(strlen("example.com"), desc.host.length);
  assert_memory_equal("example.com", desc.host.data, desc.host.length);

  CHECK_ZERO_MEMORY_ALLOCATED;
}


static void ofp_http_match_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;

  ofp_http_request_description_t desc;
  inplace_string_set(&desc.method, "GET");
  inplace_string_set(&desc.host, "example.com");
  inplace_string_set(&desc.uri, "/index.html");

  ofp_uri_list_t* uris = ofp_uri_list_new();

  ofp_uri_list_entry_t* matchEntry = NULL;
  int result = http_match(&desc, "example.com", uris, &matchEntry);
  assert_null(matchEntry);
  assert_int_equal(HttpMatchUrlNotInList, result);

  ofp_uri_list_entry_add_uri(uris, strdup("/index.html"));
  result = http_match(&desc, "example.com", uris, &matchEntry);
  assert_non_null(matchEntry);
  assert_non_null(matchEntry->uri);
  assert_int_equal(HttpMatchStartWith, result);

#if REGEX
  inplace_string_set(&desc.uri, "/phish/index.html");
  ofp_uri_list_entry_add_regex(uris, ovh_regex_new("/plop.*\\.html"));
  result = http_match(&desc, "example.com", uris, &matchEntry);
  assert_null(matchEntry);
  assert_int_equal(HttpMatchUrlNotInList, result);

  ofp_uri_list_entry_add_regex(uris, ovh_regex_new("/phish.*\\.html"));
  result = http_match(&desc, "example.com", uris, &matchEntry);
  assert_non_null(matchEntry);
  assert_non_null(matchEntry->regex);
  assert_string_equal("/phish.*\\.html", matchEntry->regex->pattern);
  assert_int_equal(HttpMatchRegex, result);

#endif

  ofp_uri_list_free_elements(uris);
  ofp_uri_list_free(uris);
  CHECK_ZERO_MEMORY_ALLOCATED;
}

static void ofp_http_check_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;

  ofp_http_request_description_t desc;
  inplace_string_set(&desc.method, "PUT");
  inplace_string_set(&desc.host, "example.com");
  inplace_string_set(&desc.uri, "/index.html");

  int result = http_check(&desc);
  assert_int_equal(HttpCheckIgnoredMethod, result);

  inplace_string_set(&desc.method, "GET");
  result = http_check(&desc);
  assert_int_equal(HttpCheckSuccess, result);

  CHECK_ZERO_MEMORY_ALLOCATED;
}

static void ofp_http_pass_through_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;

  uint8_t* tcpData = NULL;
  size_t tcpDataLength = tcmpdump_to_bin(httpGetPassThroughHeader_data, &tcpData);
  assert_int_not_equal(0, tcpDataLength);
  assert_non_null(tcpData);

  int l3offset = 0x34;
  int l3Length = tcpDataLength - l3offset;
  uint8_t* l3Data = &tcpData[l3offset];
  int result = http_has_custom_header_field(l3Data, l3Length, PASS_THROUGH_HEADER_FIELD, PASS_THROUGH_HEADER_FIELD_LEN);
  assert_int_equal(1, result);

  free(tcpData);
  CHECK_ZERO_MEMORY_ALLOCATED;
}

static void ofp_http_NO_pass_through_test(void** state)
{
  CHECK_ZERO_MEMORY_ALLOCATED;

  uint8_t* tcpData = (uint8_t*)httpGetTcpData;
  uint32_t tcpDataLength = httpGetTcpDataLength;

  int l3offset = 0x34;
  int l3Length = tcpDataLength - l3offset;
  uint8_t* l3Data = &tcpData[l3offset];
  int result = http_has_custom_header_field(l3Data, l3Length, PASS_THROUGH_HEADER_FIELD, PASS_THROUGH_HEADER_FIELD_LEN);
  assert_int_equal(0, result);

  CHECK_ZERO_MEMORY_ALLOCATED;
}



static const struct CMUnitTest tests[] = {
  cmocka_unit_test(ofp_http_get_parse_test),
  cmocka_unit_test(ofp_http_put_parse_test),
  cmocka_unit_test(ofp_http_strip_www_test),
  cmocka_unit_test(ofp_http_match_test),
  cmocka_unit_test(ofp_http_check_test),
  cmocka_unit_test(ofp_http_pass_through_test),
  cmocka_unit_test(ofp_http_NO_pass_through_test),
};

SUPPRESS_UNUSED_WARN(ofp_http_get_parse_test);
SUPPRESS_UNUSED_WARN(ofp_http_put_parse_test);
SUPPRESS_UNUSED_WARN(ofp_http_strip_www_test);
SUPPRESS_UNUSED_WARN(ofp_http_match_test);
SUPPRESS_UNUSED_WARN(ofp_http_check_test);
SUPPRESS_UNUSED_WARN(ofp_http_pass_through_test);
SUPPRESS_UNUSED_WARN(ofp_http_NO_pass_through_test);

test_helper_group(tests, suite_setup, suite_teardown);

