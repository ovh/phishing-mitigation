#ifndef __OFP_PACKET_STATS_H__
#define __OFP_PACKET_STATS_H__

#include "ofp_errors.h"

//=======================================================================================================
// Stats
//=======================================================================================================
typedef struct
{
  // Packet counts
  // Packets forwarded, by protocol (for ipv4, rest is in index 0xFF)
  uint32_t forwarded[0x100];
  uint32_t errorCodes[OFP_ERRORS_MAX_INDEX + 1];
  uint32_t ofp_dbg_frag_drop_hash_full;
  uint32_t ofp_dbg_frag_drop_too_many_retained;
  uint32_t ofp_dbg_frag_gc_could_not_send_retained;
  // Bytes in/out
  uint64_t bytesIn;
  uint64_t bytesOut;
  // Volume
  uint64_t bytesBadIp;
  uint64_t bytesParsed;
  //phish packets
  uint32_t phishPacketIn;         //Nb of packet entering phishing check code
  uint32_t phishPacketParsed;     //Nb of packet parsed by phishing code
  uint32_t phishPacketHttpGet;    //No of packet containing GET method
  uint32_t phishPacketMatch;      //Nb of packet phishing code send a RST for

  uint32_t loopCount;
} pkt_stats_s;

// This is allocated in shared memory
extern pkt_stats_s *restrict pkt_stats;


#endif //__OFP_PACKET_STATS_H__