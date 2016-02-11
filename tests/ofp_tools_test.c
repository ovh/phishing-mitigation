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
#include <string.h>
#include "tests_helpers.h"

////////////////////////////////////////////////////////////
///
/// parse_ip
///
////////////////////////////////////////////////////////////
static void parse_ip_test(void** state)
{
  (void)state;
  const char* ipStr = "192.168.10.1";
  ip_port_tuple ipPort = {0};
  int ok = parse_ip(ipStr, 0, &ipPort);
  assert_int_equal(ok, 1);
  assert_int_equal(ipPort.ip, 0xc0a80a01);
  assert_int_equal(ipPort.port, 80);
}

static void parse_ip_with_port_test(void** state)
{
  (void)state;
  const char* ipStr = "192.168.10.1:4567";
  ip_port_tuple ipPort = {0};
  int ok = parse_ip(ipStr, 0, &ipPort);
  assert_int_equal(ok, 1);
  assert_int_equal(ipPort.ip, 0xc0a80a01);
  assert_int_equal(ipPort.port, 4567);
}

////////////////////////////////////////////////////////////
///
/// ip_to_struct
///
////////////////////////////////////////////////////////////
static void ip_to_struct_test(void** state)
{
  (void)state;
  const char* ipStr = "192.168.10.1:4567";
  ip_port_tuple ipPort = {0};
  int ok = parse_ip(ipStr, 0, &ipPort);
  assert_int_equal(ok, 1);

  ip_address_t address = ip_to_struct(ipPort.ip);
  assert_int_equal(192, address.a);
  assert_int_equal(168, address.b);
  assert_int_equal(10,  address.c);
  assert_int_equal(1,   address.d);

}



////////////////////////////////////////////////////////////
///
/// patch_host_with_port
///
////////////////////////////////////////////////////////////
static void parse_host_with_no_port_test(void** state)
{
  (void)state;
  int port;
  char* inOutStr = strdup("www.example.com");
  int result = parse_host_with_port(inOutStr, &port);
  assert_int_equal(1, result);
  assert_int_equal(port, HTTP_HOSTNAME_DEFAULT_PORT);
  assert_string_equal("www.example.com", inOutStr);
  OVH_FREE(inOutStr);
}

static void parse_host_with_port_80_test(void** state)
{
  (void)state;
  int port;
  char* inOutStr = strdup("www.example.com:80");
  int result = parse_host_with_port(inOutStr, &port);
  assert_int_equal(1, result);
  assert_int_equal(port, 80);
  assert_string_equal("www.example.com", inOutStr);
  OVH_FREE(inOutStr);
}

static void parse_host_with_port_test(void** state)
{
  (void)state;
  int port;
  char* inOutStr = strdup("www.example.com:8080");
  int result = parse_host_with_port(inOutStr, &port);
  assert_int_equal(1, result);
  assert_int_equal(port, 8080);
  assert_string_equal("www.example.com:8080", inOutStr);
  OVH_FREE(inOutStr);
}


static const struct CMUnitTest tests[] = {
  cmocka_unit_test(parse_ip_test),
  cmocka_unit_test(parse_ip_with_port_test),
  cmocka_unit_test(parse_host_with_no_port_test),
  cmocka_unit_test(parse_host_with_port_80_test),
  cmocka_unit_test(parse_host_with_port_test),
  cmocka_unit_test(ip_to_struct_test),
};

SUPPRESS_UNUSED_WARN(parse_ip_test);
SUPPRESS_UNUSED_WARN(parse_ip_with_port_test);
SUPPRESS_UNUSED_WARN(parse_host_with_no_port_test);
SUPPRESS_UNUSED_WARN(parse_host_with_port_test);
SUPPRESS_UNUSED_WARN(parse_host_with_port_80_test);
SUPPRESS_UNUSED_WARN(ip_to_struct_test);

test_helper_group(tests, NULL, NULL);
