#ifndef __OFP_IPV4_H__
#define __OFP_IPV4_H__
#if TMC

#include "ofp.h"
#include "ofp_errors.h"
#include <sys/time.h>
#if TMC
#include <tmc/mem.h>
#include <tmc/alloc.h>
#endif

//=======================================================================================================
// Helper methods to access specific data in IPv4 header
//=======================================================================================================
INLINE uint32_t l3_get_ipHeaderLength(const uint8_t *const restrict l3Header)
{
  return (*(l3Header) & 0b00001111) * 4;
}

#define OFP_IPV4_OFFSET_IP_SRC 12
INLINE uint32_t l3_get_ip_src(uint8_t* l3Header)
{
  return read_uint32_t(l3Header + OFP_IPV4_OFFSET_IP_SRC);
}

#define OFP_IPV4_OFFSET_IP_DEST 16
INLINE uint32_t l3_get_ip_dest(uint8_t* l3Header)
{
  return read_uint32_t(l3Header + OFP_IPV4_OFFSET_IP_DEST);
}

INLINE uint32_t l3_get_port_src(uint8_t* l3Header, uint8_t ipHeaderLength)
{
  return *(l3Header + ipHeaderLength) * 0x100 | *(l3Header + ipHeaderLength + 1);
}

INLINE uint32_t l3_get_port_dest(uint8_t* l3Header, uint8_t ipHeaderLength)
{
  return *(l3Header + ipHeaderLength + 2) * 0x100 | *(l3Header + ipHeaderLength + 3);
}
//=======================================================================================================

//=======================================================================================================
// Packet integrity
//=======================================================================================================

// Returns 1 if packet is valid (L3-wise), <0 otherwise
static INLINE int ofp_ipv4_check_packet(netio_pkt_metadata_t *mda, netio_pkt_t *packet, const uint8_t *const l3Header)
{
  // Checksum correct ?
  if (NETIO_PKT_L3_CSUM_CALCULATED_M(mda, packet) && !NETIO_PKT_L3_CSUM_CORRECT_M(mda, packet))
  {
    PRINT_D5("IPv4 Header : invalid checksum");
    return OFP_ERR_IP_INVALID_CHECKSUM;
  }
  if (NETIO_PKT_L3_LENGTH_M(mda, packet) < 20)
  {
    PRINT_D5("IPv4 : short packet\n");
    return OFP_ERR_IP_SHORT_PACKET;
  }
  if (*l3Header < 0x45) // (4 is the version, 5 is min. IHL)
  {
    PRINT_D5("IPv4 Header : invalid IHL\n");
    return OFP_ERR_IP_INVALID_HEADER;
  }
  else if (*(l3Header+3) < 0x14 && *(l3Header+2) == 0)
  {
    PRINT_D5("IPv4 Header : invalid total length\n");
    return OFP_ERR_IP_INVALID_HEADER;
  }
  else if (*(l3Header+9) > 140)
  {
    PRINT_D5("IPv4 Header : invalid protocol\n");
    return OFP_ERR_IP_INVALID_HEADER;
  }
  // TODO check source address against reserved address blocks
  // TODO parse options (if IHL > 5) to check the length ?
  return 1;
}
//=======================================================================================================


#ifdef OFP_MAIN
//=======================================================================================================
//=======================================================================================================
// INLINE functions
// Only defined/used in ofp_main.c
// Declared that way to reduce length of ofp_main.c while still
// keeping them inlined.
//=======================================================================================================
//=======================================================================================================

//=======================================================================================================
// L4 Packet work
//=======================================================================================================
static INLINE int packet_work_l4(int work_rank, netio_pkt_t *packet, PacketList* additionalPackets);
//=======================================================================================================

//=======================================================================================================
// PACKET WORK
//=======================================================================================================
#endif // OFP_MAIN

#endif // TMC

#endif // __OFP_IPV4_H__
