#include <stdio.h>
#include "ovh_common.h"
#include "ofp_defines.h"
#include "ofp_init.h"
#include "ofp_http_perf.h"


#define REDBAR \
"=======================\n\
\t\033[31mRED BAR!\033[0m\n\
=======================\n"

#define GREENBAR \
"==========================\n\
\t\033[32mGREEN BAR!\033[0m\n\
==========================\n"


int main(int argc, char* argv[])
{
  ofp_log_startup();

  int workerCount = 29;
  ofp_init(workerCount, 0);
  ofp_init_alloc_shared(NULL);

  ofp_http_perf(argc, argv);

  printf("%s", GREENBAR);

  return 0;
}

