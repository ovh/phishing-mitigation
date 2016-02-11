#include <stdlib.h>
#include <pthread.h>
#include "ofp.h"
#include "ofp_tcp.h"


#define TCP_PSEUDO_HEADER_BUFFER_SIZE 65536
pthread_key_t tcp_pseudo_header_buffer_key;

static void tcp_pseudo_header_buffer_key_destructor(void *buffer)
{
  OVH_FREE(buffer);
}

void ofp_tcp_init_thread()
{
  pthread_setspecific(tcp_pseudo_header_buffer_key, OVH_MALLOC(TCP_PSEUDO_HEADER_BUFFER_SIZE));
}

void ofp_tcp_init(int count)
{
  pthread_key_create(&tcp_pseudo_header_buffer_key, tcp_pseudo_header_buffer_key_destructor);
}