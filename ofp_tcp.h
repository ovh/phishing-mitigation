#ifndef __OFP_TCP_H__
#define __OFP_TCP_H__

#include <memory.h>
#include <pthread.h>
#include "ofp.h"
#include "ofp_errors.h"
#include "ofp_ipv4.h"

#if TMC
#include <tmc/mem.h>
#include <tmc/spin.h>
#endif //TMC

#include "ofp_config.h"
#include "ofp_netio.h"


#define PACKET_KEEP_SOURCE_DEST 0
#define PACKET_SWAP_SOURCE_DEST 1


// Key for thread-local buffer used to store the pseudo TCP header buffer for checksum computation
extern pthread_key_t tcp_pseudo_header_buffer_key;

//=======================================================================================================

void ofp_tcp_init(int count);
void ofp_tcp_init_thread();


//=======================================================================================================
// Helper methods to access specific data in TCP header
//=======================================================================================================


INLINE uint16_t tcp_get_headerLength(uint8_t* tcpHeader)
{
  return (*(tcpHeader + 12) >> 4) * 4;
}


//=======================================================================================================

static INLINE uint8_t* find_tcp_data(uint8_t* tcpHeader)
{
  uint8_t dataOffset = *(tcpHeader+12) >> 4;
  int offset = 20;
  if (dataOffset > 5)
  {
    offset = dataOffset * 4;
  }
  return tcpHeader+offset;
}

//=======================================================================================================
// Packet integrity
//=======================================================================================================
static INLINE int check_tcp_flags(const uint32_t tcpFlags)
{
  if ((tcpFlags & 0b11) == 0b11) // FIN + SYN
  {
    PRINT_D5("Invalid TCP flags : FIN + SYN\n");
    return OFP_ERR_TCP_INVALID_HEADER;
  }
  else if ((tcpFlags & 0b101) == 0b101) // FIN + RST
  {
    PRINT_D5("Invalid TCP flags : FIN + RST\n");
    return OFP_ERR_TCP_INVALID_HEADER;
  }
  else if ((tcpFlags & 0b110) == 0b110) // SYN + RST
  {
    PRINT_D5("Invalid TCP flags : SYN + RST\n");
    return OFP_ERR_TCP_INVALID_HEADER;
  }
  else if ((tcpFlags & 0b101001) == 0b101001) // FIN + PUSH + URG
  {
    PRINT_D5("Invalid TCP flags : FIN + PUSH + URG\n");
    return OFP_ERR_TCP_INVALID_HEADER;
  }
  else if (tcpFlags == 0)
  {
    PRINT_D5("Invalid TCP flags : 0\n");
    return OFP_ERR_TCP_INVALID_HEADER;
  }
  return 1;
}

// Returns 1 if packet is valid (TCP-wise), < 0 otherwise
static INLINE int ofp_tcp_check_packet(netio_pkt_t *packet, netio_pkt_metadata_t *mda)
{
  // Checksum correct ?
  if (NETIO_PKT_L4_CSUM_CALCULATED_M(mda, packet) && !NETIO_PKT_L4_CSUM_CORRECT_M(mda, packet))
  {
    PRINT_D5("TCP Header : invalid checksum\n");
    return OFP_ERR_TCP_INVALID_CHECKSUM;
  }
  uint8_t* l3Header = (uint8_t*)NETIO_PKT_L3_DATA_M(mda, packet);
  uint8_t ipHeaderLength = l3_get_ipHeaderLength(l3Header);
  l3Header += ipHeaderLength;
  netio_pkt_inv(l3Header, 20);
  uint32_t l3Length = NETIO_PKT_L3_LENGTH_M(mda, packet);

  // Check packet length
  if (l3Length < ipHeaderLength + 20)
  {
    PRINT_D5("TCP : short packet\n");
    return OFP_ERR_TCP_SHORT_PACKET;
  }
  uint8_t tcpFlags = *(l3Header + 13);
  // Check ACK number & ACK flag
  uint32_t ackFlagSet = tcpFlags & 0b00010000;
  uint32_t ackNum = *(uint32_t*) (l3Header + 8);
  if ( (ackFlagSet && !ackNum)
    || (!ackFlagSet &&  ackNum) )
  {
    return OFP_ERR_TCP_INVALID_HEADER;
  }
  //Check ports
  if (*(uint16_t*) (l3Header) == 0
      || *(uint16_t*) (l3Header + 2) == 0)
  {
    PRINT_D5("TCP : invalid ports\n");
    return OFP_ERR_TCP_INVALID_HEADER;
  }
  // Check SEQ number
  if (*(uint32_t*) (l3Header + 4) == 0)
  {
    PRINT_D5("TCP : SEQ number empty\n");
    return OFP_ERR_TCP_INVALID_HEADER;
  }
  return check_tcp_flags(tcpFlags);
}
//=======================================================================================================


//=======================================================================================================
/*
#if DEBUG > 4
void print_tcp_datas(int rank) {
  tcp_whitelist_data *s;
  tcp_whitelist_lock(rank);
  tcp_whitelist_data *tcp_whitelist_hash = get_whitelist_hash(rank);
  if (tcp_whitelist_hash != NULL)
  {
    printf("---------------------------------\n");
    printf("Dump of tcp_datas\n");
    printf("---------------------------------\n");
    struct timeval now;
    gettimeofday(&now, NULL);
    printf("Now : %f\n", (double) now.tv_sec);
    for(s=tcp_whitelist_hash; s != NULL; s=s->hh.next)
    {
      printf("%08x:%04x=>%08x:%04x - size %d, last packet : -> %f\n", s->key.src.ip, s->key.src.port, s->key.dest.ip, s->key.dest.port,  s->streamSize, (double) s->lastPacketTime.tv_sec);
    }
    printf("---------------------------------\n");
  }
  else
  {
    printf("print_tcp_datas : tcp_datas is NULL !\n");
  }
  tcp_whitelist_unlock(rank);
}
#endif
*/

//=======================================================================================================
//=======================================================================================================
//=======================================================================================================



#endif //__OFP_TCP_H__
