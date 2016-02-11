#ifndef __OVH_TOOLS_H__
#define __OVH_TOOLS_H__

#include "ovh_common.h"


//=======================================================================================================
//
// IP tools
//
//=======================================================================================================

typedef struct
{
  unsigned char a;
  unsigned char b;
  unsigned char c;
  unsigned char d;
} ip_address_t;

#define HTTP_HOSTNAME_DEFAULT_PORT 80

/**
 * str : string containing the ip address in dotted-decimal format (ddd.ddd.ddd.ddd)
 * ip : the resulting ip
 * network_byte_order : if != 0, build resulting uint32_t in network byte order
 * Mofifies errno.
 * Returns 1 on success
 */
int parse_ip(const char *str, int network_byte_order, ip_port_tuple* result);
ip_address_t ip_to_struct(int ip);


/**
 * inOutStr : string containing the host:port
 * port : the resulting port , zero if no port found
 * inOutStr can be modified if port==80, we remove ":port" part from string "host:port"
 * Returns 1 on success
 */
int parse_host_with_port(char *inOutStr, int* port);

//=======================================================================================================
// Helper methods for byte-order conversion
//=======================================================================================================

INLINE uint32_t read_uint32_t(const uint8_t *const restrict from)
{
  return *from << 24 | *(from+1) << 16  | *(from+2) << 8 | *(from+3);
}

INLINE void fill_uint32_t(uint8_t* at, uint32_t value)
{
  *at = value >> 24 & 0xFF;
  *(at+1) = value >> 16 & 0xFF;
  *(at+2) = value >> 8 & 0xFF;
  *(at+3) = value & 0xFF;
}

INLINE uint32_t read_uint16_t(const uint8_t *const restrict from)
{
  return *from << 8 | *(from+1);
}

INLINE void fill_uint16_t(uint8_t* at, uint32_t value)
{
  *at = value >> 8 & 0xFF;
  *(at+1) = value & 0xFF;
}
//=======================================================================================================


//=======================================================================================================
// Helper methods to get diff between two timeval
//=======================================================================================================

// The current time, regularly updated by the GC thread
extern struct timeval ovh_global_cur_time;

// Returns difference between starttime & finishtime, in microseconds
long INLINE timevaldiff_usec(struct timeval *starttime, struct timeval *finishtime)
{
  long usec;
  usec=(finishtime->tv_sec-starttime->tv_sec)*1000000;
  usec+=(finishtime->tv_usec-starttime->tv_usec);
  return usec;
}

// Returns difference between starttime & finishtime, in milliseconds
long INLINE timevaldiff_msec(struct timeval *starttime, struct timeval *finishtime)
{
  return timevaldiff_usec(starttime, finishtime) / 1000;
}

long INLINE timevaldiff_sec(const struct timeval *const starttime, const struct timeval *const finishtime)
{
  return finishtime->tv_sec - starttime->tv_sec;
}

// Returns difference between starttime & finishtime, in minutes
long INLINE timevaldiff_minutes(struct timeval *starttime, struct timeval *finishtime)
{
  return (finishtime->tv_sec - starttime->tv_sec) / 60;
}
//=======================================================================================================

//=======================================================================================================
// Strings
//=======================================================================================================

//=======================================================================================================
// In place string, NOT null terminated , used to minimiez string allocation
// Data : ptr to begin of the string
// Length : size of the string
//=======================================================================================================
typedef struct
{
  char* data;
  uint32_t length;
} inplace_string_t;


void inplace_string_set(inplace_string_t* inPlaceString, char* str);


// Find next CRLF in given string
static inline char* strNextCRLF(char* data, int dataLen)
{
  if(dataLen<2) return NULL; //not enough data to store CRLF

  char* CR = (char*)memchr(data, '\r', dataLen);
  if(CR == NULL) return NULL; //CR not found

  int offset = CR - data; //offset to reach CR
  data = CR;
  dataLen -= offset;

  //enough data remaining to read CRLF ?
  if(dataLen<2) return NULL;
  if(data[1] == '\n') return data;

  return NULL;
}





#endif //__OVH_TOOLS_H__
