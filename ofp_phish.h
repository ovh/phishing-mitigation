#ifndef __OFP_PHISH_H__
#define __OFP_PHISH_H__

#include "ofp_phish_target_host_ht.h"
#include "ofp_phish_target_ip_ht.h"
#include "ofp_event_http_match.h"

#if TMC
#include <tmc/mem.h>
#include "ofp_netio.h"
#include "ofp_ipv4.h"
#include "ofp_tcp.h"
#include "ofp_http.h"
#include "ofp_packet_list.h"
#include "ofp_packet_helpers.h"

extern uint32_t phish_host_count;          //How many different host name are in phish list
extern uint32_t phish_target_count;        //How many different target url are in phish list

//=======================================================================================================
// Intitialize internal data with given phishing descriptions
//=======================================================================================================
void phish_sync();
void phish_fill_from(ofp_phish_target_host_ht_locked_t locked, ofp_phish_target_ip_ht_locked_t byIpLocked);

//=======================================================================================================
// Anti-phishing work on incoming TCP packets
// We only receive packets from clients to servers
//=======================================================================================================
static INLINE void phish_packet_work(int rank, netio_pkt_t *packet, netio_pkt_metadata_t *mda, int *sendIt, PacketList* additionalPackets)
{
  pkt_stats_s* pkt_stat = &pkt_stats[rank];
  pkt_stat->phishPacketIn++;

  ofp_phish_target_host_ht_t* hash = ofp_phish_target_by_host_get(rank);

  uint32_t packet_size = NETIO_PKT_L2_LENGTH_M(mda, packet);

  uint8_t* l3Header = (uint8_t*)NETIO_PKT_L3_DATA_M(mda, packet);
  uint8_t ipHeaderLength = l3_get_ipHeaderLength(l3Header);

  uint32_t ipSrc = l3_get_ip_src(l3Header);
  uint32_t ipDst = l3_get_ip_dest(l3Header);
  uint16_t portSrc = l3_get_port_src(l3Header, ipHeaderLength);
  uint16_t portDst = l3_get_port_dest(l3Header, ipHeaderLength);
  uint8_t tcpFlags = *(l3Header + ipHeaderLength + 13);

  PRINT_D3("RECEIVED packet %04x:%02x => %04x:%02x flags=%01x\n", ipSrc, portSrc, ipDst, portDst, tcpFlags);


  uint8_t* l2Header = (uint8_t*)NETIO_PKT_L2_DATA_M(mda, packet);
  uint16_t l3Length = NETIO_PKT_L3_LENGTH_M(mda, packet);
  netio_pkt_inv(l3Header, l3Length);
  uint8_t tcpHeaderLength = tcp_get_headerLength(l3Header + ipHeaderLength);
  uint32_t l3DataLength = l3Length - ipHeaderLength - tcpHeaderLength;
  uint32_t l3DataOffset = ipHeaderLength + tcpHeaderLength;
  uint8_t* l3Data = l3Header + l3DataOffset;

  //first check dest ip:port , if not in list, we can early return and skip heavy work
  ip_port_tuple destIpPort = {
    .ip = ipDst,
    .port = portDst
  };
  ofp_phish_target_ip_ht_t* byIpHash = ofp_phish_target_by_ip_get(rank);
  ofp_phish_target_ip_ht_locked_t byIpLocked = ofp_phish_target_by_ip_lock(byIpHash);
  ofp_phish_target_ip_t* targetByIp = ofp_phish_target_by_ip_find(byIpLocked, destIpPort);
  ofp_phish_target_by_ip_unlock(byIpLocked);
  if(targetByIp == NULL)
  {
    pkt_stat->bytesBadIp += packet_size;
    PRINT_D5("targetByIp not found, Skipping...\n");
    return;
  }

  //We do not manage packet with special flags :
  if ((tcpFlags & 0b111) != 0)  //RST SYN FIN
  {
    return;
  }

  PRINT_D5("l3Data : Offset %d, Length : %d\n", l3DataOffset, l3DataLength);
  PRINT_D3("data :\n%.*s\n", l3DataLength, l3Data);

  if(l3DataLength==0)
  {
    PRINT_D5("Length==0 : Skipping...\n");
    return;
  }

  ofp_http_request_description_t desc;
  memset(&desc, 0, sizeof(ofp_http_request_description_t));

  pkt_stat->phishPacketParsed++;
  pkt_stat->bytesParsed += packet_size;

  //parse http request header
  http_parse_result_t parse_result = http_parse(l3Data, l3DataLength, &desc);
  if(parse_result <= 0)
  {
    PRINT_D5("Failed to extract http request data\n");
    return;
  }

  int check_result = http_check(&desc);
  if(check_result <= 0)
  {
    const char* reason = http_check_result_to_str(check_result);
    PRINT_D5("http_Check failed(%s)\n", reason);
    return;
  }

  //Remove wwww. prefix
  if(!http_strip_www(&desc))
  {
    ofp_event_http_match_add(rank, HttpMatchActionPASS, EVENT_HTTP_REASON_ERROR, &desc, NULL, l3Data, l3DataLength, ipSrc, ipDst, portSrc, portDst);
    //Error ...should not occure
    return;
  }
  pkt_stat->phishPacketHttpGet++;

  ofp_phish_target_host_ht_locked_t locked = ofp_phish_target_by_host_lock(hash);

  ofp_phish_target_host_t* target = ofp_phish_target_by_host_find2(locked, desc.host.data, desc.host.length);
  if(target == NULL) //host name not in list
  {
    ofp_event_http_match_add(rank, HttpMatchActionPASS, EVENT_HTTP_MATCH_REASON_HOST_MISMATCH, &desc, NULL, l3Data, l3DataLength, ipSrc, ipDst, portSrc, portDst);
    PRINT_D5("Host not in target list : %.*s \n", desc.host.length, desc.host.data);
    ofp_phish_target_by_host_unlock(locked);
    return;
  }

  PRINT_D5("MATCH %04x:%02x %s\n", ipDst, portDst, target->host);
  //uint8_t* l3Data = find_tcp_data(l3Header);

  ofp_uri_list_entry_t* matchEntry = NULL;
  //now we can check http-request uri, method and host
  http_match_result_t match_result = http_match(&desc, target->host, target->uriList, &matchEntry);
  if( match_result > 0 )
  {
    const char* reason = http_match_result_to_str(match_result);
    const char* pattern = NULL;
    if(matchEntry != NULL)
    {
      if(match_result == HttpMatchStartWith && matchEntry->uri != NULL)
        pattern = matchEntry->uri;
      else if(match_result == HttpMatchRegex && matchEntry->regex != NULL)
        pattern = matchEntry->regex->pattern;
      else
      {
        OVH_ASSERT(TODO);
      }
    }

    int has_passthrough = http_has_custom_header_field(l3Data, l3DataLength, PASS_THROUGH_HEADER_FIELD, PASS_THROUGH_HEADER_FIELD_LEN);
    if(has_passthrough)
    {
      ofp_event_http_match_add(rank, HttpMatchActionPASS, EVENT_HTTP_MATCH_REASON_PASS_THROUGH, &desc, pattern, l3Data, l3DataLength, ipSrc, ipDst, portSrc, portDst);
      PRINT_D5("PASS_THROUGH header field found\n");
      ofp_phish_target_by_host_unlock(locked);
      return;
    }

    pkt_stat->phishPacketMatch++;
    //REVIEW : need port check too ?
    //URI is matching ! Send 2 RST packets : 1 RST to src ip , 1 RST to dst ip

    EPacket* additionalPacket = PacketListAdd(additionalPackets); //Create an additional packet
    PacketFillFromIdesc(additionalPacket, packet); //Duplicate incoming packet
    //patch this new packet to transform it to a RST packet
    //we don't need to swap src/dst since this packet is already going from client to server
    additionalPacket->channel = build_rst_packet(additionalPacket->data + additionalPacket->l2Offset, additionalPacket->data + additionalPacket->l3Offset, additionalPacket->l3Length, packet->channel, PACKET_KEEP_SOURCE_DEST);

    //patch packet to send a RST to source
    //since packet is coming from client and is going to server, we need to swap src/dst
    packet->channel = build_rst_packet(l2Header, l3Header, l3Length, packet->channel, PACKET_SWAP_SOURCE_DEST);

    ofp_event_http_match_add(rank, HttpMatchActionRST, reason, &desc, pattern, l3Data, l3DataLength, ipSrc, ipDst, portSrc, portDst);
  }
  else
  {
    const char* reason = http_match_result_to_str(match_result);
    ofp_event_http_match_add(rank, HttpMatchActionPASS, reason, &desc, NULL, l3Data, l3DataLength, ipSrc, ipDst, portSrc, portDst);
  }

  ofp_phish_target_by_host_unlock(locked);

}
//=======================================================================================================

#endif //TMC

#endif //__OFP_PHISH_H__
