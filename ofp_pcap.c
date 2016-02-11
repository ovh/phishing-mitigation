#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <tmc/task.h>
#include <tmc/alloc.h>
#include <tmc/cpus.h>

#include "ofp.h"
#include "ofp_pcap.h"
#include "ofp_netio.h"

//===============================================================

pcap_dump_hash_s pcap_dump_hash;

//===============================================================

// One per worker
ofp_pcap_dump_request_ring *pcap_dump_rings;

// 64bits bitmap
uint64_t pcap_dump_ips_last_byte[256 / 64];
uint64_t pcap_dump_ips[4294967296 / 256 / 64];
uint64_t pcap_dump_ips_bit_masks[64] = {0x1, 0x2, 0x4, 0x8,
                                        0x10, 0x20, 0x40, 0x80,
                                        0x100, 0x200, 0x400, 0x800,
                                        0x1000, 0x2000, 0x4000, 0x8000,
                                        0x10000, 0x20000, 0x40000, 0x80000,
                                        0x100000, 0x200000, 0x400000, 0x800000,
                                        0x1000000, 0x2000000, 0x4000000, 0x8000000,
                                        0x10000000, 0x20000000, 0x40000000, 0x80000000,
                                        0x100000000, 0x200000000, 0x400000000, 0x800000000,
                                        0x1000000000, 0x2000000000, 0x4000000000, 0x8000000000,
                                        0x10000000000, 0x20000000000, 0x40000000000, 0x80000000000,
                                        0x100000000000, 0x200000000000, 0x400000000000, 0x800000000000,
                                        0x1000000000000, 0x2000000000000, 0x4000000000000, 0x8000000000000,
                                        0x10000000000000, 0x20000000000000, 0x40000000000000, 0x80000000000000,
                                        0x100000000000000, 0x200000000000000, 0x400000000000000, 0x800000000000000,
                                        0x1000000000000000, 0x2000000000000000, 0x4000000000000000, 0x8000000000000000
                                        };


//===============================================================

static INLINE void write_pcap_header(FILE *pcapFile)
{
    pcap_hdr_t globalHeader = {
      0xa1b2c3d4,
      2,
      4,
      0,
      0,
      MAX_CAPTURE_LENGTH,
      1 // LINKTYPE_ETHERNET
    };
    fwrite(&globalHeader, sizeof(pcap_hdr_t), 1, pcapFile);
}

static INLINE int pcap_mkdir_if_needed(char *dirName)
{
  int dirOk = 0;
  struct stat dirStat;
  if (stat(dirName, &dirStat) != 0)
  {
    if (errno == ENOENT)
    {
      // Does not exist, mkdir
      if (mkdir(dirName, S_IRWXU) == 0)
      {
        dirOk = 1;
      }
      else
      {
        PRINT_ERR("Failed to mkdir %s : %s\n", dirName, strerror(errno));
      }
    }
    else
    {
      PRINT_ERR("Failed to stat %s : %s\n", dirName, strerror(errno));
    }
  }
  else if (dirStat.st_mode & S_IFDIR)
  {
    dirOk = 1;
  }
  else
  {
    PRINT_ERR("%s is not a directory !\n", dirName, strerror(errno));
  }
  return dirOk;
}



static void pcap_build_doing_filename(const pcap_dump_info *restrict info, int sendIt, char* filename)
{
  PCAP_BUILD_FILENAME(info, sendIt, filename, "doing");
}

static void pcap_build_done_filename(const pcap_dump_info *restrict info, int sendIt, char* filename)
{
  PCAP_BUILD_FILENAME(info, sendIt, filename, "done");
}

static INLINE void flush_pcap_file(FILE *pcapFile)
{
  if ( fflush(pcapFile) )
  {
    PRINT_ERR("Could not fflush pcap dump file : %s\n", strerror(errno));
  }
  if ( fsync(fileno(pcapFile)) )
  {
    PRINT_ERR("Could not fsync pcap dump file : %s\n", strerror(errno));
  }
}

static void close_pcap_file(pcap_dump_info* info, int sendIt, FILE *pcapFile)
{
  flush_pcap_file(pcapFile);
  if ( fclose(pcapFile) )
  {
    PRINT_ERR("Could not close pcap dump file : %s\n", strerror(errno));
  }

  char filenameDoing[64];
  char filenameDone[64];
  pcap_build_doing_filename(info, sendIt, filenameDoing);
  pcap_build_done_filename(info, sendIt, filenameDone);
  if ( rename(filenameDoing, filenameDone) )
  {
    PRINT_ERR("Could not rename %s to %s : %s\n", filenameDoing, filenameDone, strerror(errno));
  }
}

static void close_files(pcap_dump_info* info)
{
  FILE *pcapFile = info->forwarded;
  if (pcapFile)
  {
    close_pcap_file(info, 1, pcapFile);
  }
  for (int i=0; i < OFP_ERRORS_MAX_INDEX + 1; i++)
  {
    FILE *pcapFile = info->dropped[i];
    if (pcapFile)
    {
      close_pcap_file(info, -i, pcapFile);
    }
  }
  info->forwarded = NULL;
  memset(info->dropped, 0, sizeof(info->dropped));
  info->curTime.tv_sec = 0;
  info->bytesDumped = 0;
  info->ioErr = 0;
}

static void flush_files(pcap_dump_info* info)
{
  FILE *pcapFile = info->forwarded;
  if (pcapFile)
  {
    flush_pcap_file(pcapFile);
  }
  for (int i=0; i < OFP_ERRORS_MAX_INDEX + 1; i++)
  {
    FILE *pcapFile = info->dropped[i];
    if (pcapFile)
    {
      flush_pcap_file(pcapFile);
    }
  }
}




//===============================================================
static INLINE pcap_dump_info* pcap_dump_hash_get_ip(uint32_t ip)
{
  pcap_dump_info *info = NULL;
  OVH_HASH_FIND(&pcap_dump_hash, &ip, ip, sizeof(ip), info);
  return info;
}


void pcap_dump_hash_add_ip(uint32_t ip, char *ipStr, int code, int updateStartTime)
{
  tmc_spin_mutex_lock(&pcap_dump_hash.mutex);
  pcap_dump_info *info = pcap_dump_hash_get_ip(ip);
  if (!info)
  {
    info = OVH_CALLOC(1, sizeof(*info));
    info->ip = ip;
    OVH_HASH_ADD_KEYPTR(&pcap_dump_hash, &(info->ip), sizeof(uint32_t), info);
    PRINT_INFO("Starting pcap dump for %s\n", ipStr);
    info->ipStr = ipStr;
    info->code = code;
    info->sampling = 1000;
    info->start = ovh_global_cur_time.tv_sec;
  }
  if (info)
  {
    if (updateStartTime)
      info->start = ovh_global_cur_time.tv_sec;
    info->curTime = ovh_global_cur_time;
  }
  else
  {
    PRINT_ERR("Cound not allocate struct pcap_dump_info !\n");
  }
  tmc_spin_mutex_unlock(&pcap_dump_hash.mutex);
}


void pcap_dump_clear_bit(uint32_t ip)
{
  pcap_dump_ips[(ip & 0xFFFFFF) / 64] |= pcap_dump_ips_bit_masks[ip & 63];
  uint32_t destIpLastByte = ip >> 24;
  if (pcap_dump_ips_last_byte[destIpLastByte / 64] & pcap_dump_ips_bit_masks[destIpLastByte & 63])
    pcap_dump_ips_last_byte[destIpLastByte / 64] ^= pcap_dump_ips_bit_masks[destIpLastByte & 63];
}

void ofp_pcap_refresh_dumps(int closeFiles)
{
  pcap_dump_info *info=NULL, *tmp=NULL;
  OVH_HASH_ITER(&pcap_dump_hash, info, tmp)
  {
    if (closeFiles)
    {
      close_files(info);
    }
    else
    {
      flush_files(info);
    }
    // Setting this will have the IP removed from the hash if pcap_dump_hash_add_ip() is not called before ofp_pcap_cleanup_hash()
    info->curTime.tv_sec = 0;
  }
}

void ofp_pcap_cleanup_hash(void (*delCallback)(uint32_t))
{
  pcap_dump_info *info=NULL, *tmp=NULL;
  pcap_dump_hash_s* hash = &pcap_dump_hash;
  OVH_HASH_ITER(hash, info, tmp)
  {
    // If info->curTime hasn't been updated, it means the IP is no longer in the conf file of IPs to dump
    if ( ! info->curTime.tv_sec)
    {
      PRINT_INFO("Stopping pcap dump for %s\n", info->ipStr);
      close_files(info);
      (*delCallback)(info->ip);
      OVH_HASH_DEL(hash, info);
      OVH_FREE(info);
    }
  }
  OVH_ASSERT(OVH_HASH_COUNT(hash) == 0);
  OVH_HASH_CLEAR(hash); //reset stats
}




static INLINE FILE* open_pcap_file(const pcap_dump_info *restrict info, int packetSendIt)
{
  // Check if we need to create the IP's directories before dumping in it
  int dirOk = 0;
  char dirName[64];
  char dirDoingName[64];
  char dirDoneName[64];
  sprintf(dirName, PCAP_OUTPUT_FOLDER "%s", info->ipStr);
  if ( pcap_mkdir_if_needed(dirName) )
  {
    sprintf(dirDoingName, PCAP_OUTPUT_FOLDER "%s/doing", info->ipStr);
    if (pcap_mkdir_if_needed(dirDoingName) )
    {
      sprintf(dirDoneName, PCAP_OUTPUT_FOLDER "%s/done", info->ipStr);
      if (pcap_mkdir_if_needed(dirDoneName) )
      {
        dirOk = 1;
      }
    }
  }

  FILE *pcapFile = NULL;
  if (dirOk)
  {
    char filename[64];
    pcap_build_doing_filename(info, packetSendIt, filename);
    pcapFile = fopen(filename, "w");
    if (pcapFile != NULL) {
      write_pcap_header(pcapFile);
    }
  }
  return pcapFile;
}

static INLINE void pcap_info_adjust_sampling(pcap_dump_info *const restrict info)
{
  if (info->curTime.tv_sec)
  {
    float bps = info->bytesDumped * info->sampling * 8 * (((float)(1000 - (info->curTime.tv_usec / 1000))) / 1000);
    info->sampling = ((uint32_t) bps / MAX_DUMPED_BPS_PER_IP) + 1;
    info->bytesDumped = 0;
  }
  info->curTime = ovh_global_cur_time;
  info->curTime.tv_usec = 0;
}

static INLINE void dump_pcap(const ofp_pcap_dump_request *const restrict request, pcap_dump_info *const restrict info)
{
  if (info->bytesDumped * 8 > MAX_DUMPED_BPS_PER_IP)
  {
    // Update bytesDumped so it will be taken into account when recalculating the sampling rate, but don't actually write anything
    info->bytesDumped += request->packetLength;
    return;
  }

  FILE *pcapFile = NULL;
  int packetSendIt = request->packetSendIt;
  if (packetSendIt <= 0)
  {
    pcapFile = info->dropped[-packetSendIt];
  }
  else
  {
    pcapFile = info->forwarded;
  }
  if (pcapFile == NULL && !info->ioErr)
  {
    pcapFile = open_pcap_file(info, packetSendIt);
    if (packetSendIt <= 0)
    {
      info->dropped[-packetSendIt] = pcapFile;
    }
    else
    {
      info->forwarded = pcapFile;
    }
  }

  if (pcapFile)
  {
    pcaprec_hdr_t header;

    uint32_t packetLength = request->packetLength;

    uint32_t capturedLength = packetLength > MAX_CAPTURE_LENGTH ? MAX_CAPTURE_LENGTH : packetLength;
    header.ts_sec = ovh_global_cur_time.tv_sec;
    header.ts_usec = ovh_global_cur_time.tv_usec;
    header.incl_len = capturedLength;
    header.orig_len = packetLength;

    // TODO handle errors on writes
    fwrite(&header, sizeof(pcaprec_hdr_t), 1, pcapFile);

    fwrite(request->buffer, header.incl_len, 1, pcapFile);

    info->bytesDumped += packetLength;
  }
  else if (!info->ioErr)
  {
    PRINT_ERR("WARN : could not create pcap dump file : %s\n", strerror(errno));
    info->ioErr = 1;
  }
}

static INLINE ofp_pcap_dump_request ofp_pcap_dump_request_pull(int rank)
{
  ofp_pcap_dump_request_ring *const pcap_dump_ring = pcap_dump_rings + rank;
  ofp_pcap_dump_request result = {0};
  tmc_spin_mutex_lock(&pcap_dump_ring->mutex);
  if (pcap_dump_ring->curReadIndex != pcap_dump_ring->curWriteIndex)
  {
    pcap_dump_ring->curReadIndex++;
    if (pcap_dump_ring->curReadIndex >= OFP_PCAP_DUMP_REQUEST_RING_SIZE)
      pcap_dump_ring->curReadIndex = 0;
    memcpy(&result, pcap_dump_ring->requests + pcap_dump_ring->curReadIndex, sizeof(result));
  }
  tmc_spin_mutex_unlock(&pcap_dump_ring->mutex);
  return result;
}

void ofp_pcap_check_and_dump()
{
  for (int rank = 0; rank < work_size; rank++)
  {
    ofp_pcap_dump_request request = ofp_pcap_dump_request_pull(rank);
    if (request.buffer)
    {
      pcap_dump_info* info = pcap_dump_hash_get_ip(request.ip);
      if (info)
      {
        // Check if packets matches the requested code for dumping, then check sampling
        if ( (
              info->code == 0
              || (info->code == 256 && request.packetSendIt > 0)
              || (info->code == -256 && request.packetSendIt < 0)
              || info->code == request.packetSendIt
             )
             && (info->packetCount++ % info->sampling) == 0 )
        {
          dump_pcap(&request, info);
          info->packetDumped++;
        }
        if ( info->curTime.tv_sec!= ovh_global_cur_time.tv_sec)
        {
          pcap_info_adjust_sampling(info);
        }
      }
      gxio_mpipe_push_buffer(mpipe_context, request.stackId, request.buffer);
    }
  }
}

void ofp_pcap_init()
{
  pcap_dump_rings = OVH_CALLOC(work_size, sizeof(*pcap_dump_rings));
}
