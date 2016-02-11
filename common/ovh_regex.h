#ifndef __OVH_REGEX_H__
#define __OVH_REGEX_H__

#if REGEX

#include <pcre.h>               /* PCRE lib        NONE  */
#include "ovh_mempool.h"

//=======================================================================================================
// Internal struct describing a regex
//=======================================================================================================
typedef struct _ovh_regex
{
  pcre* compiled;
  pcre_extra* extra;
  char* pattern;
  struct _ovh_regex *mp_next;
} ovh_regex_t;

extern ovh_mempool *ovh_regex_mempool;
#define OVH_REGEX_MEMPOOL_SIZE 100000


//=======================================================================================================
// Init & Destroy
//=======================================================================================================
void ovh_regex_alloc_shared(tmc_alloc_t *alloc);
void ovh_regex_free_shared();


//=======================================================================================================
// Helpers
//=======================================================================================================
ovh_regex_t* ovh_regex_new(const char* pattern);
ovh_regex_t* ovh_regex_clone(ovh_regex_t* regex);
int ovh_regex_match2(ovh_regex_t* regex, const char* subject, uint32_t subjectLength);
static INLINE int ovh_regex_match(ovh_regex_t* regex, const char* subject)
{
  return ovh_regex_match2(regex, subject, strlen(subject));
}

void ovh_regex_free(ovh_regex_t* regex);

#endif //REGEX

#endif //__OVH_REGEX_H__
