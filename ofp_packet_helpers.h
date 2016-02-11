#ifndef __OFP_PACKET_HELPER_H__
#define __OFP_PACKET_HELPER_H__

#include <memory.h>
#include <pthread.h>
#include "ofp.h"
#include "ofp_netio.h"
#include "ofp_channels.h"
#include "ofp_tcp.h"

//=======================================================================================================
// Checksum
//=======================================================================================================

static INLINE uint16_t compute_checksum(uint8_t *data, uint16_t size)
{
  uint32_t sum = 0;
  uint32_t *b = (uint32_t *) data;

  /* Loop unrolling, 32 bytes at a time */
  while (size >= 32)
  {
    uint32_t s = *b;
    sum += s;
    if (sum < s) sum++;
    s = *(b+1);
    sum += s;
    if (sum < s) sum++;
    s = *(b+2);
    sum += s;
    if (sum < s) sum++;
    s = *(b+3);
    sum += s;
    if (sum < s) sum++;
    s = *(b+4);
    sum += s;
    if (sum < s) sum++;
    s = *(b+5);
    sum += s;
    if (sum < s) sum++;
    s = *(b+6);
    sum += s;
    if (sum < s) sum++;
    s = *(b+7);
    sum += s;
    if (sum < s) sum++;

    size -= 32;
    b += 8;
  }
  /* Loop unrolling, 16 bytes at a time */
  while (size >= 16)
  {
    uint32_t s = *b;
    sum += s;
    if (sum < s) sum++;
    s = *(b+1);
    sum += s;
    if (sum < s) sum++;
    s = *(b+2);
    sum += s;
    if (sum < s) sum++;
    s = *(b+3);
    sum += s;
    if (sum < s) sum++;

    size -= 16;
    b += 4;
  }
  /* Loop unrolling, 8 bytes at a time */
  while (size >= 8)
  {
    uint32_t s = *b;
    sum += s;
    if (sum < s) sum++;
    s = *(b+1);
    sum += s;
    if (sum < s) sum++;
    s = *(b+2);

    size -= 8;
    b += 2;
  }

  /* Handle tail less than 8 bytes long */
  if (size & 4)
  {
    uint32_t s = *b++;
    sum += s;
    if (sum < s) sum++;
    size -= 4;
  }
  data = (uint8_t *) b;
  if (size & 2)
  {
    uint16_t s = *(uint16_t *) data;
    sum += s;
    if (sum < s) sum++;
    data += 2;
  }
  if (size & 1)
  {
    uint8_t s = *(uint8_t *) data;
    sum += s;
    if (sum < s) sum++;
  }

  uint16_t t1, t2;

  /* Fold down to 16 bits */
  t1 = sum;
  t2 = sum >> 16;
  t1 += t2;
  if (t1 < t2) t1++;

  return ~t1;
}

static INLINE void compute_ip_checksum(uint8_t *l3Header, uint8_t ipHeaderLength)
{
  //TODO
}

static INLINE void compute_tcp_checksum(uint8_t *l3Header, int l3length)
{
  uint8_t ipHeaderLength = (*(l3Header) & 0b00001111) * 4;
  uint16_t *tcpHeader = (uint16_t*) l3Header + (ipHeaderLength / 2);
  uint16_t tcpLength = l3length - ipHeaderLength;

  memset(l3Header + ipHeaderLength + 16, 0, 2);
  uint16_t *pseudoTcpHeader = (uint16_t*) pthread_getspecific(tcp_pseudo_header_buffer_key);
  // IPs
  memcpy(pseudoTcpHeader, l3Header + 12, 8);
  // Protocol
  *(pseudoTcpHeader + 4) = 0x0600;
  // TCP length
  *(pseudoTcpHeader + 5) = (tcpLength << 8 & 0XFF00) | tcpLength >> 8;
  // TCP Header + Payload
  memcpy(pseudoTcpHeader + 6, tcpHeader, tcpLength);
  *(tcpHeader + 8) = compute_checksum((uint8_t*)pseudoTcpHeader, 12 + tcpLength);
}
//=======================================================================================================




//=======================================================================================================
// Packet building/manipulation
//=======================================================================================================

static INLINE void packet_swap_source_destination(uint8_t* l2Header, uint8_t* l3Header)
{

  uint16_t* etherType = (uint16_t*)l2Header;
  netio_pkt_inv(etherType, 12);

  // Don't swap ethernet addresses as they are those of the routers surrounding the tilera
  if(config_bridge_mode)
  {
    //Temp in dev mode we need to swap mac
    uint16_t tmp[3];
    memcpy(&tmp, etherType, 6);
    memcpy(etherType, etherType+3, 6);
    memcpy(etherType+3, &tmp, 6);
  }

  netio_pkt_inv(l3Header, 20);

  uint8_t ipHeaderLength = l3_get_ipHeaderLength(l3Header);
  /*
  uint8_t tcpHeaderLength = tcp_get_headerLength(l3Header + ipHeaderLength);
  netio_pkt_inv(l3Header + ipHeaderLength, tcpHeaderLength);
  */

  // Swap IPs
  uint32_t tmp32;
  memcpy(&tmp32, l3Header+16, 4);
  memcpy(l3Header+16, l3Header+12, 4);
  memcpy(l3Header+12, &tmp32, 4);

  // Swap ports
  uint16_t tmp16;
  memcpy(&tmp16, l3Header+ipHeaderLength+2, 2);
  memcpy(l3Header+ipHeaderLength+2, l3Header+ipHeaderLength, 2);
  memcpy(l3Header+ipHeaderLength, &tmp16, 2);

  //netio_pkt_finv();
}

static INLINE void packet_swap_source_destination_from_packet(netio_pkt_t *packet, netio_pkt_metadata_t *mda)
{
  uint8_t* l2Header = (uint8_t*)NETIO_PKT_L2_DATA_M(mda, packet);
  uint8_t* l3Header = (uint8_t*)NETIO_PKT_L3_DATA_M(mda, packet);
  return packet_swap_source_destination(l2Header, l3Header);
}

static INLINE int build_rst_packet(uint8_t* l2Header, uint8_t* l3Header, int l3HeaderLength, int channel, int swapSourceDest)
{
  if(swapSourceDest)
  {
    packet_swap_source_destination(l2Header, l3Header);
  }

  uint8_t ipHeaderLength = l3_get_ipHeaderLength(l3Header);
  //uint8_t tcpHeaderLength = tcp_get_headerLength(l3Header + ipHeaderLength);

  // Set IPv4 identification to 0
  //TODO need this ? if we change something in IPv4 header, we need to call compute_ip_checksum 
  //memset(l3Header+4, 0, 2);
  // Set RST flag
  *(l3Header + ipHeaderLength + 13) = 0b00000100;
  // Set window size to 0
  fill_uint16_t(l3Header + ipHeaderLength + 14, 0);

  if(swapSourceDest)
  {
    // Set SEQ number to received ACK
    fill_uint32_t(l3Header + ipHeaderLength + 4, read_uint32_t(l3Header + ipHeaderLength + 8) );
  }

  // Set ACK number to 0
  fill_uint32_t(l3Header + ipHeaderLength + 8, 0);
  // Remove options
  memset(l3Header + ipHeaderLength + 20, 0, ((*(l3Header + ipHeaderLength + 12) >> 4) - 5) * 4);

  //compute_ip_checksum(l3Header, ipHeaderLength);

  compute_tcp_checksum(l3Header, l3HeaderLength);


  if(swapSourceDest)
  {
    channel = ofp_netio_get_output_channel(channel); //make as if packet was comming from the output
  }

  //netio_pkt_flush(l3Header, ipHeaderLength + tcpHeaderLength);
  //netio_pkt_fence();
  netio_pkt_finv();

  return channel;
}

static INLINE int build_rst_packet_from_packet(netio_pkt_t *packet, netio_pkt_metadata_t *mda, int swapSourceDest)
{
  uint8_t* l2Header = (uint8_t*)NETIO_PKT_L2_DATA_M(mda, packet);
  uint8_t* l3Header = (uint8_t*)NETIO_PKT_L3_DATA_M(mda, packet);
  int l3HeaderLength = NETIO_PKT_L3_LENGTH_M(mda, packet);

  return build_rst_packet(l2Header, l3Header, l3HeaderLength, swapSourceDest, packet->channel);
}
//=======================================================================================================


#endif //__OFP_PACKET_HELPER_H__
