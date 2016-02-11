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
#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
// So we can backtrace if we segfault
#include <execinfo.h>
#if TMC
#include <tmc/task.h>
#include <tmc/alloc.h>
#include <tmc/cpus.h>
#endif //TMC

#include "ovh_common.h"
#include "ovh_log.h"
#include "ovh_tools.h"

// =========================================================================================
// Debug printing
// =========================================================================================

void debug_printf(const char* prefix, const char *fileName, const char *function, int line, const char *fmt, ...)
{
#if OVH_VALGRIND
  //stop HG flood, make debug_printf thread safe
  tmc_spin_mutex_lock(&debug_printf_mutex);
#endif
  struct tm *locTime = localtime(&(ovh_global_cur_time.tv_sec));
  static char dateStr[64];
  strftime(dateStr, 64, "%c", locTime);
  fprintf(stdout, "[%s][%s]", prefix, dateStr);
  if (fileName!=NULL && function!=NULL)
    fprintf(stdout, "[%s:%d %s()]", fileName, line, function);
  fprintf(stdout, " ");
  va_list args;
  va_start(args, fmt);
  vfprintf(stdout, fmt, args);
  va_end(args);
#if OVH_VALGRIND
  tmc_spin_mutex_unlock(&debug_printf_mutex);
#endif
}

void printHex(uint8_t* data, uint32_t size)
{
  for (int j = 0; j < size; j++)
  {
    if (j > 0) printf(":");
    printf("%02X", data[j]);
  }
  printf("\n");
}

void log_backtrace()
{
  void *array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "BackTrace :\n");
  backtrace_symbols_fd(array, size, 2);
}


// =========================================================================================
// Format
// =========================================================================================
const char bytes_units[] = {
  0,
  'K',
  'M',
  'G'
};


void format_human(long bytes, char *buf)
{
  if (bytes == 0)
  {
    sprintf(buf, "             0  B");
    return;
  }
  int max_exponent = sizeof(bytes_units) - 1;
  int exponent = 0;
  long e = 1;
  while (e * 1024 < bytes && exponent < max_exponent) {
    e *= 1024;
    exponent++;
  }
  long value = bytes / e;
  sprintf(buf, "%14ld ", value);
  size_t buflen = strlen(buf);
  if (bytes_units[exponent])
  {
    sprintf(buf+buflen, "%cB", bytes_units[exponent]);
  }
  else
  {
    sprintf(buf+buflen, " B");
  }
}

