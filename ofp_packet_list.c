#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <tmc/task.h>
#include <tmc/alloc.h>
#include <tmc/cpus.h>
#include <assert.h>

#include "ofp.h"
#include "ofp_packet_list.h"
#include "ofp_netio.h"


PacketList* PacketListNew(uint32_t capacity)
{
  PacketList* res = (PacketList *) OVH_MALLOC(sizeof(PacketList));
  memset(res, 0, sizeof(PacketList));
  res->capacity = capacity;

  res->packets = (EPacket*) OVH_MALLOC(sizeof(EPacket) * capacity);
  memset(res->packets, 0, sizeof(EPacket*) * capacity);

  PacketListClear(res);
  return res;
}


//Fill EPacket fields from a gxio_mpipe_idesc_t struct
//Replace buffer with a copy, so we can poke it as much as we want
int PacketFillFromIdesc(EPacket* packet, gxio_mpipe_idesc_t* idesc)
{
  gxio_mpipe_edesc_t* edesc = &packet->edesc;
  packet->channel = idesc->channel;
  gxio_mpipe_edesc_copy_idesc(edesc, idesc); //create edesc from idesc

  void* buf = (uint8_t* )gxio_mpipe_pop_buffer(mpipe_context, idesc->stack_idx); //request a new buffer

  // FIXME: Handle this properly.
  OVH_ASSERT(buf);

  memcpy(buf, gxio_mpipe_idesc_get_va(idesc), idesc->l2_size);
  edesc->va = (uintptr_t)buf; //assign new buf to edesc

  // Use MF to make sure memcpy's have completed before we
  // send the packets.
  __insn_mf();

  //get interesting l2+l3 information while we can get it from idesc
  packet->data = buf;
  packet->l2Offset = gxio_mpipe_idesc_get_l2_offset(idesc);
  packet->l2Length = gxio_mpipe_idesc_get_l2_length(idesc);
  packet->l3Offset = gxio_mpipe_idesc_get_l3_offset(idesc);
  packet->l3Length = gxio_mpipe_idesc_get_l3_length(idesc);

  return 1;
}

