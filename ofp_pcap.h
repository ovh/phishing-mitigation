#ifndef __OFP_PCAP_H__
#define __OFP_PCAP_H__

#include <sys/stat.h>
#include <tmc/spin.h>
#include "uthash.h"

#define PCAP_SECONDS_PER_FILE 10
#define MAX_DUMPED_BPS_PER_IP (10 * 1024 * 1024) // 10Mbps
#define PCAP_MAX_FILE_INDEX 60

typedef struct
{
  uint32_t ip;
  int packetSendIt;
  uint32_t packetLength;
  void *buffer;
  unsigned int stackId; // Used to push the buffer back to the mPipe
} ofp_pcap_dump_request;

#define OFP_PCAP_DUMP_REQUEST_RING_SIZE 100
typedef struct
{
  tmc_spin_mutex_t mutex;
  ofp_pcap_dump_request requests[OFP_PCAP_DUMP_REQUEST_RING_SIZE];
  uint32_t curReadIndex;
  uint32_t curWriteIndex;
} ofp_pcap_dump_request_ring;


typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

#define PCAP_OUTPUT_FOLDER "/home/ofp_pcap/"
#define MAX_CAPTURE_LENGTH 1520
#define MAX_PCAP_FILE_SIZE 100000000
#define MAX_PCAP_FILE_INDEX 20



// One per worker
extern ofp_pcap_dump_request_ring *pcap_dump_rings;

// 64bits bitmap
extern uint64_t pcap_dump_ips_last_byte[256 / 64];
extern uint64_t pcap_dump_ips[4294967296 / 256 / 64];
extern uint64_t pcap_dump_ips_bit_masks[64];


//===============================================================
// Hash for the IPs we're dumping
//===============================================================
typedef struct
{
  uint32_t ip;
  char *ipStr;
  // Codes ('sendIt') we should dump
  // 0 : everything
  // 1-255 : corresponding L4 protocol
  // 256 : all forwarded packets
  // -(1-255) : dropped packets w/ corresponding error code
  // -256 : all dropped packets
  int code;
  // Pcap files for packets forwarded
  FILE* forwarded;
  // Pcap files for packets dropped, by error code
  FILE* dropped[OFP_ERRORS_MAX_INDEX + 1];
  int ioErr; // Set if we had an error opening a file or writing to it. Reset every time we file rotate
  uint32_t start; // Timestamp at which we started this dump
  uint64_t bytesDumped;
  struct timeval curTime;
  uint32_t packetDumped;
  uint32_t packetCount;
  uint32_t sampling; // '1000' at first, adjusted every second to match MAX_DUMPED_BPS_PER_IP
  UT_hash_handle hh;
} pcap_dump_info;

typedef struct
{
  tmc_spin_mutex_t mutex;
  pcap_dump_info *head;
  UT_hash_table tbl; /* uthash needed */
} pcap_dump_hash_s;



extern pcap_dump_hash_s pcap_dump_hash;


#define PCAP_BUILD_FILENAME(info, sendIt, filename, subfolder) \
do { \
  if (sendIt <= 0) \
  { \
    sprintf(filename, PCAP_OUTPUT_FOLDER "%s/" subfolder "/%u_drop_%d.pcap", info->ipStr, info->start, -sendIt); \
  } \
  else \
  { \
    sprintf(filename, PCAP_OUTPUT_FOLDER "%s/" subfolder "/%u_fwd.pcap", info->ipStr, info->start); \
  } \
} while (0)



void ofp_pcap_init();

void ofp_pcap_check_and_dump();

void pcap_dump_clear_bit(uint32_t ip);

void ofp_pcap_refresh_dumps(int closeFiles);

void ofp_pcap_cleanup_hash(void (*delCallback)(uint32_t));

void pcap_dump_hash_add_ip(uint32_t ip, char *ipStr, int code, int updateStartTime);


//===============================================================


#ifdef OFP_MAIN
//===============================================================
// INLINE functions
// Only defined/used in ofp_main.c
// Declared that way to reduce length of ofp_main.c while still
// keeping them inlined.
//===============================================================

static INLINE void ofp_pcap_dump_request_push(ofp_pcap_dump_request *request, int rank)
{
  ofp_pcap_dump_request_ring *const pcap_dump_ring = pcap_dump_rings + rank;
  tmc_spin_mutex_lock(&pcap_dump_ring->mutex);
  if (pcap_dump_ring->curWriteIndex == pcap_dump_ring->curReadIndex -1
    || (pcap_dump_ring->curWriteIndex == OFP_PCAP_DUMP_REQUEST_RING_SIZE-1 && pcap_dump_ring->curReadIndex == 0))
  {
    // No room left in ring, give up this dump
    gxio_mpipe_push_buffer(mpipe_context, request->stackId, request->buffer);
  }
  else
  {
    pcap_dump_ring->curWriteIndex++;
    if (pcap_dump_ring->curWriteIndex >= OFP_PCAP_DUMP_REQUEST_RING_SIZE)
      pcap_dump_ring->curWriteIndex = 0;
    memcpy(pcap_dump_ring->requests + pcap_dump_ring->curWriteIndex, request, sizeof(*request));
  }
  tmc_spin_mutex_unlock(&pcap_dump_ring->mutex);
}


#endif // OFP_MAIN

#endif // __OFP_PCAP_H__
