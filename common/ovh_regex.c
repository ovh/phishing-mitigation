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
#if REGEX
#include <stdio.h>              /* I/O lib         C89   */
#include <stdlib.h>             /* Standard Lib    C89   */
#include <string.h>             /* Strings         C89   */

#include "ovh_defines.h"
#include "ovh_regex.h"
#include "ovh_log.h"
#include "ovh_mempool.h"
#include "ovh_alloc.h"

ovh_mempool *ovh_regex_mempool = NULL;

void ovh_regex_alloc_shared(tmc_alloc_t *alloc)
{
  OVH_MEMPOOL_CREATE_SHARED(ovh_regex_mempool, ovh_regex_t, OVH_REGEX_MEMPOOL_SIZE, alloc);
}

void ovh_regex_free_shared()
{
  OVH_MEMPOOL_DISCARD_SHARED(ovh_regex_mempool);
}

void ovh_regex_free(ovh_regex_t* regex)
{
  OVH_ASSERT(regex != NULL);

  //Free duplicated str
  OVH_FREE(regex->pattern);

  // Free up the regular expression.
  pcre_free(regex->compiled);

  // Free up the EXTRA PCRE value (may be NULL at this point)
  if(regex->extra != NULL)
    pcre_free(regex->extra);

  OVH_MEMPOOL_FREE(*ovh_regex_mempool, regex);
}

ovh_regex_t* ovh_regex_new(const char* pattern_arg)
{
  OVH_ASSERT(pattern_arg != NULL);
  char* pattern = strdup(pattern_arg);

  ovh_regex_t* result = NULL;
  OVH_MEMPOOL_ALLOC_ZEROED(*ovh_regex_mempool, result);

  const char *pcreErrorStr;
  int pcreErrorOffset;
  static char tmpPattern[2046];
  OVH_ASSERT( (strlen(pattern) + 1) < sizeof(tmpPattern)); //check no buffer overflow, +1 since we prepend begin regex char '^'
  snprintf(tmpPattern, sizeof(tmpPattern), "^%s", pattern);

  // First, the regex string must be compiled.
  pcre* reCompiled = pcre_compile(tmpPattern, 0, &pcreErrorStr, &pcreErrorOffset, NULL);

  /* OPTIONS (second argument) (||'ed together) can be:
       PCRE_ANCHORED       -- Like adding ^ at start of pattern.
       PCRE_CASELESS       -- Like m//i
       PCRE_DOLLAR_ENDONLY -- Make $ match end of string regardless of \n's
                              No Perl equivalent.
       PCRE_DOTALL         -- Makes . match newlins too.  Like m//s
       PCRE_EXTENDED       -- Like m//x
       PCRE_EXTRA          --
       PCRE_MULTILINE      -- Like m//m
       PCRE_UNGREEDY       -- Set quantifiers to be ungreedy.  Individual quantifiers
                              may be set to be greedy if they are followed by "?".
       PCRE_UTF8           -- Work with UTF8 strings.
  */

  // pcre_compile returns NULL on error, and sets pcreErrorOffset & pcreErrorStr
  if(reCompiled == NULL) {
    PRINT_ERR("ERROR: Could not compile '%s': %s\n", tmpPattern, pcreErrorStr);
    return NULL;
  }

// Optimize the regex
  pcre_extra* pcreExtra = pcre_study(reCompiled, 0, &pcreErrorStr);

  /* pcre_study() returns NULL for both errors and when it can not optimize the regex.  The last argument is how one checks for
     errors (it is NULL if everything works, and points to an error string otherwise. */
  if(pcreErrorStr != NULL) {
    PRINT_ERR("ERROR: Could not study '%s': %s\n", tmpPattern, pcreErrorStr);
    return NULL;
  } /* end if */

  result->compiled = reCompiled;
  result->extra = pcreExtra;
  result->pattern = pattern;

  return result;
}

ovh_regex_t* ovh_regex_clone(ovh_regex_t* regex)
{
  OVH_ASSERT(regex != NULL);
  return ovh_regex_new(regex->pattern);
}


int ovh_regex_match2(ovh_regex_t* regex, const char* subject, uint32_t subjectLength)
{
  OVH_ASSERT(regex != NULL);
  //PRINT_D5("ovh_regex_match2(%s vs '%.*s')\n", regex->Pattern, subjectLength, subject);

  int subStrVec[30];
  /* Try to find the regex in aLineToMatch, and report results. */
  int pcreExecRet = pcre_exec(regex->compiled,
                          regex->extra,
                          subject,
                          subjectLength,  // length of string
                          0,                      // Start looking at this point
                          0,                      // OPTIONS
                          subStrVec,
                          30);                    // Length of subStrVec

  /* pcre_exec OPTIONS (||'ed together) can be:
     PCRE_ANCHORED -- can be turned on at this time.
     PCRE_NOTBOL
     PCRE_NOTEOL
     PCRE_NOTEMPTY */

  if(pcreExecRet == PCRE_ERROR_NOMATCH) return 0; //no match, just return 0

  if(pcreExecRet < 0) { // Something bad happened..
    switch(pcreExecRet) {
    case PCRE_ERROR_NULL         : PRINT_ERR("Something was null\n");                      break;
    case PCRE_ERROR_BADOPTION    : PRINT_ERR("A bad option was passed\n");                 break;
    case PCRE_ERROR_BADMAGIC     : PRINT_ERR("Magic number bad (compiled re corrupt?)\n"); break;
    case PCRE_ERROR_UNKNOWN_NODE : PRINT_ERR("Something kooky in the compiled re\n");      break;
    case PCRE_ERROR_NOMEMORY     : PRINT_ERR("Ran out of memory\n");                       break;
    default                      : PRINT_ERR("Unknown error\n");                           break;
    } /* end switch */
    return 0;
  }

    // At this point, rc contains the number of substring matches found...
  if(pcreExecRet == 0) {
    PRINT_ERR("But too many substrings were found to fit in subStrVec!\n");
    return 0;
  } /* end if */



  return 1;

}
#endif //REGEX