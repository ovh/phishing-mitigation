#ifndef _OFP_DEFINE_H_
#define _OFP_DEFINE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>

#define OFP_STD_LOG "/var/log/tilera-phishing/tilera-phishing.log"

#define INLINE inline __attribute__((always_inline))

#ifndef TMC
#error TMC not defined, check your Makefile
#endif

#ifndef TWOINTERFACE
#define TWOINTERFACE 0
#endif

#ifndef MODE_VLAN
#define MODE_VLAN 0
#endif

#ifndef OFP_PROFILING
#define OFP_PROFILING 0
#endif

#ifndef OFP_LOOP_STATISTICS
#define OFP_LOOP_STATISTICS 0
#endif

#ifndef PASS_THROUGH_HEADER_FIELD
#error PASS_THROUGH_HEADER_FIELD not defined
//PASS_THROUGH_HEADER_FIELD="X-randomkey"
#endif
#define PASS_THROUGH_HEADER_FIELD_LEN (sizeof(PASS_THROUGH_HEADER_FIELD)-1)


#endif //_OFP_DEFINE_H_
