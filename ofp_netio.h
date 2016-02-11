#ifndef __OFP_NETIO_H__
#define __OFP_NETIO_H__

#include "ofp_packet_stats.h"

#if TMC

#if TILEGX
#include <gxio/mpipe.h>
#else
#include <netio/netio.h>
#endif
#include <arch/atomic.h>
#include "ofp_errors.h"
#include "ofp_packet_list.h"
#include "ofp_config.h"
#include "ofp_channels.h"
#include "ofp_workers.h"
#include "ofp_main.h"

#if MODE_VLAN
#define ETHER_HEADER_LENGTH 18
#else
#define ETHER_HEADER_LENGTH 14
#endif

//=======================================================================================================

#if TILEGX
extern gxio_mpipe_context_t *mpipe_context;

extern char** interfaces;
// Array containing the channel numbers for each link we handle
#else //TILEPRO
extern char *interface1;
extern char *interface2;
#endif

// Netio queues of each worker
extern NETIO_IQUEUE_T **queues1;
#if TILEGX
// On Gx, we can have simply have on iqueue per worker, for any number of links.
// We do need one equeue per link.
// We then use the 'channel' field in gxio_mpipe_idesc_t to figure out where to egress the packet
// Thus, we build a 2D array : equeuesW[worker_rank % max_equeues][channel]
extern NETIO_EQUEUE_T ***equeuesW;
// Max. equeues per link
extern int max_equeues;
extern int stack_idx_small_buf;
extern int stack_idx_large_buf;
#else // TILEPRO
extern NETIO_EQUEUE_T **equeues1;
#if TWOINTERFACE
extern NETIO_IQUEUE_T **queues2;
extern NETIO_EQUEUE_T **equeues2;
#endif
#endif // /TILEPRO

#if TILEGX
void ofp_mpipe_init();
void ofp_mpipe_start();
#else
void ofp_netio_queue_config(int work_rank, netio_queue_t *queue, int qid,char *interface, int recv);
void ofp_netio_flow_config(netio_queue_t *queue, netio_group_t* flowtbl, int base, unsigned count);
void ofp_netio_group_config(netio_queue_t *queue, netio_group_t* flowtbl, int base, int count);
#endif

#define OFP_IPV4_PROTO_ICMP 1
#define OFP_IPV4_PROTO_TCP 6
#define OFP_IPV4_PROTO_UDP 17

//=======================================================================================================

#ifdef OFP_MAIN
//===============================================================
// INLINE functions
// Only defined/used in ofp_main.c
// Declared that way to reduce length of ofp_main.c while still
// keeping them inlined.
//===============================================================

// Test for a new packet without blocking.
// Returns a valid status
static INLINE int
#if TILEGX
ofp_netio_packet_pull(NETIO_IQUEUE_T *queue, gxio_mpipe_idesc_t **idescs)
#else // TILEPRO
ofp_netio_packet_pull(NETIO_IQUEUE_T *queue, netio_pkt_t *pkt)
#endif // /TILEPRO
{
#if TILEGX
  int n = gxio_mpipe_iqueue_try_peek(queue, idescs);
  return n >= 0 ? 1 : n;
#else
  return netio_get_packet(queue, pkt) == NETIO_PKT;
#endif
}


#if TILEGX
static INLINE void ofp_netio_additional_packet_push(const int work_rank, NETIO_EQUEUE_T **equeues, PacketList* additionalPackets)
{
  OVH_ASSERT(additionalPackets->count>=0);

  if(additionalPackets->count <= 0)
  {
    return;
  }

  /*
  //TODO
  pkt_stats[work_rank].bytesOut += packet_size;
  pkt_stats[work_rank].forwarded[sendIt]++;
  */

  //TODO manage multiple channel list
  EPacket* packet = PacketListGet(additionalPackets, 0);
  NETIO_EQUEUE_T* queue = ofp_netio_get_equeue_from_channel(equeues, packet->channel);

  for (;;)
  {
    netio_error_t err = NETIO_NO_ERROR;

    PRINT_D5("worker %d/%d : sending %d additionals packets on queue with channel %d[#%d]\n", work_rank, work_size, additionalPackets->count, queue->channel, ofp_netio_channel_to_index(queue->channel));
    int64_t slot = gxio_mpipe_equeue_reserve_fast(queue, additionalPackets->count);
    if (slot < 0)
    {
      err = (int)slot;
      PRINT_D5("gxio_mpipe_equeue_reserve_fast() failed with error %d\n", err);
    }
    else
    {
      for (int i = 0; i < additionalPackets->count; ++i)
      {
        EPacket* packet = PacketListGet(additionalPackets, i);
        PRINT_D5("worker %d/%d : sending 1 additional packet with channel %d[#%d]\n", work_rank, work_size, packet->channel, ofp_netio_channel_to_index(packet->channel));
        gxio_mpipe_equeue_put_at(queue, packet->edesc, slot + i);
      }
    }

    if (err == NETIO_NO_ERROR)
    {
      PRINT_D5("worker %d/%d : done, waiting next\n", work_rank, work_size);
      PRINT_D1(".");
      break;
    }

    PRINT_D3("worker %d/%d : got big problem, dying\n", work_rank, work_size);
    PRINT_D1("D");
    tmc_task_die("couldn't send packet, status %d: %s", err, netio_strerror(err));
  }
}
#endif // /TILEPRO



// Dispose of an old packet by sending or releasing.
// This retries a temporary busy status.
//
static INLINE void
#if TILEGX
ofp_netio_packet_push(const int work_rank, NETIO_IQUEUE_T *iqueue, NETIO_EQUEUE_T* queue, netio_pkt_t *packet, gxio_mpipe_edesc_t *edesc, const uint32_t packet_size, const int sendIt)
#else // TILEPRO
ofp_netio_packet_push(const int work_rank, NETIO_IQUEUE_T *iqueue, NETIO_EQUEUE_T* queue, netio_pkt_t *packet, const uint32_t packet_size, const int sendIt)
#endif // /TILEPRO
{
  if (sendIt <= 0)
  {
    pkt_stats[work_rank].errorCodes[-sendIt]++;
  }
  else
  {
    pkt_stats[work_rank].bytesOut += packet_size;
    pkt_stats[work_rank].forwarded[sendIt]++;
  }
  for (;;)
  {
    netio_error_t err = NETIO_NO_ERROR;
    if (sendIt <= 0 || packet_drop)
    {
      PRINT_D4("worker %d/%d : droping because sendIt=%i & packet_drop=%i\n", work_rank, work_size, sendIt, packet_drop);
      PRINT_D1("d");
#if TILEGX
      if (edesc->hwb)
      {
        gxio_mpipe_iqueue_drop(iqueue, packet);
      }
#else
      err = netio_free_buffer(iqueue, packet);
#endif
    }
    else if (sendIt > 0)
    {
      PRINT_D5("worker %d/%d : sending packet with channel %d[#%d] on queue with channel %d[#%d]\n", work_rank, work_size, packet->channel, ofp_netio_channel_to_index(packet->channel), queue->channel, ofp_netio_channel_to_index(queue->channel));
#if TILEGX
      int64_t slot = gxio_mpipe_equeue_reserve_fast(queue, 1);
      if (slot < 0)
        err = (int)slot;
      else
        gxio_mpipe_equeue_put_at(queue, *edesc, slot);
#else
      err = netio_send_packet(queue, packet);
#endif
    }
    if (err == NETIO_NO_ERROR)
    {
      PRINT_D5("worker %d/%d : done, waiting next\n", work_rank, work_size);
      PRINT_D1(".");
      break;
    }
#if !TILEGX
// FIXME Can this happen on GX ? If so, what's the error code ?
    if (err == NETIO_QUEUE_FULL)
    {
      PRINT_D3("worker %d/%d : queue full , waiting a litle\n", work_rank, work_size);
      PRINT_D1("W");
      continue;
    }
#endif
    PRINT_D3("worker %d/%d : got big problem, dying\n", work_rank, work_size);
    PRINT_D1("D");
    tmc_task_die("couldn't send packet, status %d: %s",
             err, netio_strerror(err));
  }
}

#if MODE_VLAN
static uint16_t etherTypeVlanValue = 0x0081;
static uint16_t vlanMask = 0xFF0F;
static uint16_t vlanMaskReset =  0x00F0;

static INLINE void ofp_netio_packet_swap_vlan(int work_rank, uint16_t *etherTypeVlan, int *sendIt)
{
  PRINT_D5("worker %d/%d", work_rank, work_size);

#if (DEBUG > 3)
  printf(" got mac source=");
  uint8_t i=0;
  for (i = 0; i <= 2; i++) { printf("%04x ",*(etherTypeVlan+(i))); }
  etherTypeVlan+=3;
  printf(" dest=");
  for (i = 0; i <= 2; i++) { printf("%04x ",*(etherTypeVlan+(i))); }
  etherTypeVlan+=3;
  printf(" ");
#else
  etherTypeVlan+=6;
#endif

  if ( *etherTypeVlan == etherTypeVlanValue)
  {
    if ( *(etherTypeVlan+2) == 0x0008  // ipv4
        || *(etherTypeVlan+2) == 0x0608  // arp
        || *(etherTypeVlan+2) == 0x3580  // rarp
        || *(etherTypeVlan+2) == 0xdd86 // ipv6
       )
    {
      // we are in a 801.1q vlan , check vlan
      etherTypeVlan+=1;

      //printf("worker %d/%d , got etherTypeVlan=%04x", work_rank, work_size,*etherTypeVlan);
      PRINT_D3(" , got Vlan=%04x",*etherTypeVlan);
      uint16_t vlan= *etherTypeVlan & vlanMask;
      PRINT_D3(" , maskedVlan=%04x",vlan);
      if (vlan == packet_vlan_swap1)
      {
        *etherTypeVlan &= vlanMaskReset;
        *etherTypeVlan |= packet_vlan_swap2;

        PRINT_D2(" new =%04x",*etherTypeVlan);
      }
      else if (vlan == packet_vlan_swap2)
      {
        *etherTypeVlan &= vlanMaskReset;
        *etherTypeVlan |= packet_vlan_swap1;

        PRINT_D2(" new =%04x",*etherTypeVlan);
      }
      else
      {
        // should discard it
        PRINT_D2(" bad vlan=%04x\n",vlan);
        *sendIt = 0;
      }

    }
    // TODO should we still discard it ? (this is only in MODE_VLAN
    else if (
        *(etherTypeVlan+2) == 0x3200 // spanning tree protocol , do not forward !!
        )
    {
      PRINT_D2(" spanning tree protocal on vlan %04x discarding\n",*(etherTypeVlan+1));
      *sendIt = 0;
    }
    else
    {
      // should discard it
      //printf("worker %d/%d , bad etherType inside=%04x\n", work_rank, work_size,*(etherTypeVlan+2));
      PRINT_D2(" , bad etherType inside=%04x before=%04x %04x start=%04x after=%04x  it=%04x %04x \n", *(etherTypeVlan+2), *(etherTypeVlan-2),*(etherTypeVlan-1),*(etherTypeVlan),*(etherTypeVlan+1),*(etherTypeVlan+2),*(etherTypeVlan+3));
      *sendIt = 0;
    }
  }
  else if (
      *etherTypeVlan == 0x0501 // cisco truc much , do not forward
      )
  {
    PRINT_D2(" cisco internal protocol %04x discarding\n",*etherTypeVlan);
    *sendIt = 0;
  }
  else
  {
    // should discard it
    PRINT_D2(" , bad etherTypeVlan=%04x before=%04x %04x after=%04x %04x %04x\n",*etherTypeVlan,*(etherTypeVlan-2),*(etherTypeVlan-1),*(etherTypeVlan+1),*(etherTypeVlan+2),*(etherTypeVlan+3));
    *sendIt = 0;
  }
  // Flush 12 bytes of modified packet to memory.
  netio_pkt_finv(etherTypeVlan, 2);
  netio_pkt_fence();
}
#endif // MODE_VLAN
#endif //OFP_MAIN


#endif //TMC

#endif //__OFP_NETIO_H__
