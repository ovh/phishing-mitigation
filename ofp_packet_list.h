#ifndef __OFP_PACKET_LIST_H__
#define __OFP_PACKET_LIST_H__

#if TMC
#if TILEGX
#include <gxio/mpipe.h>
#else
#include <netio/netio.h>
#endif
#include <arch/atomic.h>

#include "ofp_errors.h"

//=======================================================================================================
// Out packet data description
//=======================================================================================================
typedef struct
{
  gxio_mpipe_edesc_t edesc;
  uint8_t* data;
  uint32_t l2Offset;
  uint32_t l2Length;
  uint32_t l3Offset;
  uint32_t l3Length;
  int channel;
} EPacket;


//=======================================================================================================
// Manage a list of EPacket
// Preallocated capacity during init
//=======================================================================================================
typedef struct
{
  EPacket *packets;
  uint32_t count;
  uint32_t capacity;
} PacketList;


PacketList* PacketListNew(uint32_t capacity);

static inline EPacket* PacketListAdd(PacketList* list)
{
  OVH_ASSERT(list->count < list->capacity);
  if(list->count >= list->capacity)
  {
    return NULL;
  }

  uint32_t index = list->count;
  EPacket* packet = list->packets + index;
  list->count++;

  return packet;
}

static inline EPacket* PacketListGet(PacketList* list, int index)
{
  OVH_ASSERT(index < list->count);
  EPacket* packet = list->packets + index;

  return packet;
}

static inline int PacketListClear(PacketList* list)
{
  list->count = 0;

  return 1;
}

int PacketFillFromIdesc(EPacket* packet, gxio_mpipe_idesc_t* idesc);


#endif // TMC
#endif //__OFP_PACKET_LIST_H__
