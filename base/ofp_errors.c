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
#include "ofp_errors.h"

char* str_errors[OFP_ERRORS_MAX_INDEX + 1] = {
  "Retained for analysis",
  "Short IP packet",
  "Invalid IP Header",
  "Invalid IP Checksum",
  "Bad fragment",
  "Short TCP packet",
  "Invalid TCP Header",
  "Invalid TCP Checksum",
  "Short UDP packet",
  "Invalid UDP Checksum",
  "SYN AUTH flow not in whitelist",
  "DNS AMP rate-limited",
  "UDP rate-limited",
  "Out of memory",
  "NTP Amp"
};

const char* ofp_strerror(int errCode)
{
  errCode = -errCode;
  if (errCode < 0 || errCode > OFP_ERRORS_MAX_INDEX)
  {
    return NULL;
  }
  else
  {
    return str_errors[errCode];
  }
}
