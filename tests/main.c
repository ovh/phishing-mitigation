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


void* __wrap_malloc(size_t size)
{
  return test_malloc(size);
}
SUPPRESS_UNUSED_WARN(__wrap_malloc);

void* __wrap_calloc(size_t nbelem, size_t size)
{
  return test_calloc(nbelem, size);
}
SUPPRESS_UNUSED_WARN(__wrap_calloc);

void* __wrap_realloc(void* ptr, size_t size)
{
  return test_realloc(ptr, size);
}
SUPPRESS_UNUSED_WARN(__wrap_realloc);

void __wrap_free(void* ptr)
{
  test_free(ptr);
}
SUPPRESS_UNUSED_WARN(__wrap_free);



static int g_failed_count = 0;

void test_helper_report_failed(int count)
{
  g_failed_count += count;
}

int main(int argc, char* argv[])
{
  ofp_log_startup();

  if(g_failed_count!=0)
  {
    printf("%s", REDBAR);
  }
  //green bar displayed by makefile...

  return g_failed_count;
}

