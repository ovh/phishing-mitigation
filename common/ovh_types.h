#ifndef __OVH_TYPES_H__
#define __OVH_TYPES_H__

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>


typedef struct
{
  uint32_t ip;
  uint16_t port;
} ip_port_tuple;

#if TMC
//=======================================================================================================
// Let's define structures & macros common to netio (tilepro) and mpipe (tilegx)
//=======================================================================================================
#if TILEGX
#define netio_pkt_metadata_t void
#define NETIO_PKT_METADATA(...) NULL

#define netio_pkt_t gxio_mpipe_idesc_t

#define NETIO_IQUEUE_T gxio_mpipe_iqueue_t
#define NETIO_EQUEUE_T gxio_mpipe_equeue_t

#define NETIO_PKT_L2_LENGTH_M(dummy, idesc) gxio_mpipe_idesc_get_l2_length(idesc)
#define NETIO_PKT_L2_DATA_M(dummy, idesc) gxio_mpipe_idesc_get_l2_start(idesc)
#define NETIO_PKT_L3_LENGTH_M(dummy, idesc) gxio_mpipe_idesc_get_l3_length(idesc)
#define NETIO_PKT_L3_DATA_M(dummy, idesc) gxio_mpipe_idesc_get_l3_start(idesc)
#define NETIO_PKT_L3_CSUM_CALCULATED_M(...) true
#define NETIO_PKT_L3_CSUM_CORRECT_M(dummy, idesc) ((gxio_mpipe_idesc_get_status(idesc) & 0x80) == 0)
#define NETIO_PKT_L4_CSUM_CALCULATED_M(...) true
#define NETIO_PKT_L4_CSUM_CORRECT_M(dummy, idesc) (idesc->cs && idesc->csum_seed_val == 0xFFFF)
#define NETIO_PKT_FLOW_HASH_M(dummy, idesc) gxio_mpipe_idesc_get_flow_hash(idesc)

#define netio_error_t int
#define NETIO_NO_ERROR 0
#define netio_strerror gxio_strerror

#define netio_pkt_finv(...) __insn_mf()
#define netio_pkt_fence()

// Shouldn't be necessary on GX
#define NETIO_PKT_INV_METADATA_M(...)
#define netio_pkt_inv(l2data, size) tmc_mem_finv_no_fence(l2data, size)

#else // TILEPRO
#define NETIO_IQUEUE_T netio_queue_t
#define NETIO_EQUEUE_T netio_queue_t
#endif

#endif //TMC
#endif //__OVH_TYPES_H__
