#ifndef __TEST_DATA_H__
#define __TEST_DATA_H__

#include <stdint.h>

extern uint8_t httpGetTcpData[];
extern uint32_t httpGetTcpDataLength;

extern uint8_t httpPutTcpData[];
extern uint32_t httpPutTcpDataLength;

extern const char* httpGetPassThroughHeader_data;

size_t tcmpdump_to_bin(const char* tcmpdump_arg, uint8_t** result);


#endif //__TEST_DATA_H__