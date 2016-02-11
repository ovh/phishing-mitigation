#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <tmc/task.h>
#include <tmc/alloc.h>
#include <tmc/cpus.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "ofp.h"
#include "ofp_main.h"
#include "ofp_config_ip.h"
#include "ofp_phish.h"
#include "ofp_logger.h"
#include "ofp_main.h"
#include "ofp_ipv4.h"
#include "ofp_config.h"
#include "ofp_pcap.h"

//#define PRINT_FLOOD(...) PRINT_D5(__VA_ARGS__)
#define PRINT_FLOOD(...) NO_OP(__VA_ARGS__)

#define OFP_SYSLOG_FILE "/var/log/tilera-phishing/access.log"
#define OFP_MEMORY_USAGE_LOG_FILE "/dev/shm/tilera-phishing-memory.log"
#define OFP_HASH_USAGE_LOG_FILE "/dev/shm/tilera-phishing-hash.log"
#define LOG_FILE "/dev/shm/tilera-phishing-summary.log"
#define DETAILS_LOG_FILE "/dev/shm/tilera-phishing-details.log"
#define RAW_LOG_FILE "/dev/shm/tilera-phishing-raw.log"
#define RAW_LOG_MAX_FILE_SIZE 1000000
#define RAW_LOG_MAX_INDEX 9
#define CHAR_PER_COLLUMN 70

uint64_t logger_loop_duration_ms = 0;

struct sockaddr_in ofp_logger_addr = {0};

static gxio_mpipe_stats_t mpipeStats = {0};

#define LOGGER_SECS_INTERVAL 1
#define LOGGER_MS_INTERVAL 1000

static const pkt_stats_s EMPTY_PKT_STATS;
static pkt_stats_s pkt_stats_prev;
static pkt_stats_s pkt_stats_now;
static pkt_stats_s pkt_stats_diff;
static pkt_stats_s pkt_stats_tmp[36];

static INLINE FILE* open_log_file(char* logFilePath)
{
  FILE *logFile = fopen(logFilePath, "r+");
  if (logFile == NULL) {
    logFile = fopen(logFilePath, "w");
  }
  return logFile;
}

static INLINE FILE* open_log_file_append(char* logFilePath)
{
  FILE *logFile = fopen(logFilePath, "a");
  if (logFile == NULL) {
    logFile = fopen(logFilePath, "w");
  }
  return logFile;
}

// Truncate any remainings in the file
static INLINE void truncate_log_file(FILE *logFile)
{
  long fileLength = ftell(logFile);
  ftruncate(fileno(logFile), fileLength);
}


static void logger_print_line_separator(FILE *logFile)
{
  static int lineWidth = 0;
  static char *line;
  if (lineWidth == 0)
  {
    lineWidth = 112;
    line = (char*) OVH_MALLOC(lineWidth + 2);
    memset(line, '-', lineWidth);
    line[lineWidth] = '\n';
    line[lineWidth+1] = '\0';
  }
  fprintf(logFile, "%s", line);
}

/*
 * ofp_logger_append_number
 *
 * Append and uint64_t number to a buffer in text mode
 */
#define ofp_logger_append_number(buf, number, totalLength) \
do { \
  static char __tmp[32];  \
  memset(__tmp, 0, 32);   \
  sprintf(__tmp, "%lu;", (uint64_t)number); \
  int __len = strlen(__tmp);  \
  memcpy(buf+totalLength, __tmp, __len); \
  totalLength += __len;  \
} while (0)


/*
 * ofp_logger_send_udp
 *
 * Send vac-game stats through UDP for rrd loggin
 *
 * Warning: If you add field here. You will need to update the rrd script
 * in the state-collector directory.
 * This will erase all previous stats
 */
void send_stats_udp(const uint32_t timestamp, uint32_t max_mempool_usage, uint32_t max_hash_usage, float cyclePerPkt)
{
  if (ofp_logger_addr.sin_addr.s_addr && ofp_logger_addr.sin_port)
  {
    static char buf[2048];
    memset(buf, 0, 2048);
    int totalLength = 0;
    // 0 : timestamp
    ofp_logger_append_number(buf, timestamp, totalLength);
    // 1 : ingress_packets
    ofp_logger_append_number(buf, mpipeStats.ingress_packets, totalLength);
    // 2 : ingress_bytes
    ofp_logger_append_number(buf, mpipeStats.ingress_bytes, totalLength);
    // 3 : egress_packets
    ofp_logger_append_number(buf, mpipeStats.egress_packets, totalLength);
    // 4 : egress_bytes
    ofp_logger_append_number(buf, mpipeStats.egress_bytes, totalLength);
    // 5 : ingress_drops
    ofp_logger_append_number(buf, mpipeStats.ingress_drops, totalLength);
    // 6 : ingress_drops_no_buf
    ofp_logger_append_number(buf, mpipeStats.ingress_drops_no_buf, totalLength);
    // 7 : ingress_drops_ipkt
    ofp_logger_append_number(buf, mpipeStats.ingress_drops_ipkt, totalLength);
    // 8 : ingress_drops_cls_lb
    ofp_logger_append_number(buf, mpipeStats.ingress_drops_cls_lb, totalLength);
    // 9 : forwarded (icmp)
    ofp_logger_append_number(buf, pkt_stats_now.forwarded[1], totalLength);
    // 10 : forwarded (tcp)
    ofp_logger_append_number(buf, pkt_stats_now.forwarded[6], totalLength);
    // 11 : forwarded (udp)
    ofp_logger_append_number(buf, pkt_stats_now.forwarded[17], totalLength);
    // 12 : forwarded (other)
    ofp_logger_append_number(buf, pkt_stats_now.forwarded[0], totalLength);


    // 13 : no more used
    ofp_logger_append_number(buf, 0, totalLength);
    // 14 : no more used
    ofp_logger_append_number(buf, 0, totalLength);
    // 15 : phishPacketMatch
    ofp_logger_append_number(buf, pkt_stats_now.phishPacketMatch, totalLength);
    // 16 : logger_loop_duration_ms
    ofp_logger_append_number(buf, logger_loop_duration_ms, totalLength);

    // 17 - 87 : dropped by error code
    for(int err=0; err < OFP_ERRORS_MAX_INDEX + 1; err++)
    {
      ofp_logger_append_number(buf, pkt_stats_now.errorCodes[err], totalLength);
    }

    // 88
    ofp_logger_append_number(buf, pkt_stats_now.bytesBadIp, totalLength);
    // 89
    ofp_logger_append_number(buf, pkt_stats_now.bytesParsed, totalLength);
    // 90
    ofp_logger_append_number(buf, pkt_stats_now.loopCount, totalLength);
    // 91
    ofp_logger_append_number(buf, max_mempool_usage, totalLength);

    // 92 : phish_host_count
    ofp_logger_append_number(buf, phish_host_count, totalLength);
    // 93 : phish_target_count
    ofp_logger_append_number(buf, phish_target_count, totalLength);


    // 94 :
    ofp_logger_append_number(buf, pkt_stats_now.phishPacketIn, totalLength);
    // 95 :
    ofp_logger_append_number(buf, pkt_stats_now.phishPacketParsed, totalLength);
    // 96 :
    ofp_logger_append_number(buf, pkt_stats_now.phishPacketHttpGet, totalLength);
    // 97 :
    ofp_logger_append_number(buf, max_hash_usage, totalLength);
    // 98 :
    ofp_logger_append_number(buf, cyclePerPkt, totalLength);

    // 99 -> 100 : Free slot
    ofp_logger_append_number(buf, 0, totalLength);
    ofp_logger_append_number(buf, 0, totalLength);


    buf[totalLength] = 0;

    int sockfd, slen=sizeof(ofp_logger_addr);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
      PRINT_ERR("Error opening socket : %s\n", strerror(errno));

    ofp_logger_addr.sin_family = AF_INET;

    PRINT_FLOOD("sending stats : size = %d\n", totalLength + 1);
    if (sendto(sockfd, buf, totalLength+1, 0, (struct sockaddr*)&ofp_logger_addr, slen)==-1)
      PRINT_ERR("Error sendto : %s\n", strerror(errno));

    close(sockfd);
  }
}

void ofp_logger_pkt_stats()
{
  pkt_stats_now = EMPTY_PKT_STATS;
  pkt_stats_diff = EMPTY_PKT_STATS;
  memcpy(pkt_stats_tmp, pkt_stats, sizeof(pkt_stats_tmp));

  // Aggregate all worker stats in one
  for (int rank = 0; rank < work_size; rank++)
  {
    // For forwarded packets, we only care about the following protocols : ICMP (1), TCP (6) & UDP (17)
    // We put everything else in index 0
    for (int proto = 0; proto <= 0xFF; proto++)
    {
      switch (proto)
      {
        case OFP_IPV4_PROTO_ICMP:
        case OFP_IPV4_PROTO_TCP:
        case OFP_IPV4_PROTO_UDP:
          pkt_stats_now.forwarded[proto] += pkt_stats_tmp[rank].forwarded[proto];
          break;
        default:
          pkt_stats_now.forwarded[0] += pkt_stats_tmp[rank].forwarded[proto];
      }
    }
    pkt_stats_now.bytesIn += pkt_stats_tmp[rank].bytesIn;
    pkt_stats_now.bytesOut += pkt_stats_tmp[rank].bytesOut;
    pkt_stats_now.bytesBadIp += pkt_stats_tmp[rank].bytesBadIp;
    pkt_stats_now.bytesParsed += pkt_stats_tmp[rank].bytesParsed;
    pkt_stats_now.loopCount += pkt_stats_tmp[rank].loopCount > 0 ? 0 : 1;
    for(int err=0; err < OFP_ERRORS_MAX_INDEX + 1; err++)
    {
      pkt_stats_now.errorCodes[err] += pkt_stats_tmp[rank].errorCodes[err];
    }

    pkt_stats_now.phishPacketMatch += pkt_stats_tmp[rank].phishPacketMatch;

    pkt_stats_now.phishPacketIn += pkt_stats_tmp[rank].phishPacketIn;
    pkt_stats_now.phishPacketParsed += pkt_stats_tmp[rank].phishPacketParsed;
    pkt_stats_now.phishPacketHttpGet += pkt_stats_tmp[rank].phishPacketHttpGet;
  }

  // Compute pkt_stats diffs
  for (int proto = 0; proto <= 0xFF; proto++)
  {
    pkt_stats_diff.forwarded[proto] = pkt_stats_now.forwarded[proto] - pkt_stats_prev.forwarded[proto];
  }
  pkt_stats_diff.bytesIn = pkt_stats_now.bytesIn - pkt_stats_prev.bytesIn;
  pkt_stats_diff.bytesOut = pkt_stats_now.bytesOut - pkt_stats_prev.bytesOut;
  pkt_stats_diff.bytesBadIp = pkt_stats_now.bytesBadIp - pkt_stats_prev.bytesBadIp;
  pkt_stats_diff.bytesParsed = pkt_stats_now.bytesParsed - pkt_stats_prev.bytesParsed;
  for(int err=0; err < OFP_ERRORS_MAX_INDEX + 1; err++)
  {
    pkt_stats_diff.errorCodes[err] = pkt_stats_now.errorCodes[err] - pkt_stats_prev.errorCodes[err];
  }

  pkt_stats_diff.phishPacketMatch = pkt_stats_now.phishPacketMatch - pkt_stats_prev.phishPacketMatch;

  pkt_stats_diff.phishPacketIn = pkt_stats_now.phishPacketIn - pkt_stats_prev.phishPacketIn;
  pkt_stats_diff.phishPacketParsed = pkt_stats_now.phishPacketParsed - pkt_stats_prev.phishPacketParsed;
  pkt_stats_diff.phishPacketHttpGet = pkt_stats_now.phishPacketHttpGet - pkt_stats_prev.phishPacketHttpGet;

}

void ofp_logger_dump_hash_tables_usage(uint32_t* max_hash_usagePtr)
{
  FILE* file = open_log_file(OFP_HASH_USAGE_LOG_FILE);
  if (file == NULL)
  {
    PRINT_ERR("Failed to open %s\n", OFP_HASH_USAGE_LOG_FILE);
    return;
  }

  logger_print_line_separator(file);
  fprintf(file, "Hash                                  | %% used  |   items  | 1+ chain | 2+ chain | 4+ chain | 8+ chain | Buckets \n");
  logger_print_line_separator(file);

  double hash_usage = 0.0;
  uint32_t max_hash_usage = 0;

  OVH_LOG_HASH_TABLE(file, config_desc_hash, hash_usage);
  max_hash_usage = OVH_MAX(max_hash_usage, 100 * hash_usage);

  OVH_LOG_HASH_TABLE(file, config_host_hash, hash_usage);
  max_hash_usage = OVH_MAX(max_hash_usage, 100 * hash_usage);

  OVH_LOG_HASH_TABLE(file, config_ip_hash, hash_usage);
  max_hash_usage = OVH_MAX(max_hash_usage, 100 * hash_usage);

  pcap_dump_hash_s* pcap_dump_hash_ptr = &pcap_dump_hash; //To fix compile error : "‘&pcap_dump_hash’ will always evaluate as ‘true’"
  OVH_LOG_HASH_TABLE(file, pcap_dump_hash_ptr, hash_usage);
  max_hash_usage = OVH_MAX(max_hash_usage, 100 * hash_usage);

#if 1
  //hash table per workers are duplicated, only log rank=0
  int rank = 0;
  ofp_phish_target_host_ht_t* targetByHost = PhishTargetHostHashes + rank;
  OVH_LOG_HASH_TABLE(file, targetByHost, hash_usage);
  max_hash_usage = OVH_MAX(max_hash_usage, 100 * hash_usage);

  ofp_phish_target_ip_ht_t* targetByIp = PhishTargetIpHashes + rank;
  OVH_LOG_HASH_TABLE(file, targetByIp, hash_usage);
  max_hash_usage = OVH_MAX(max_hash_usage, 100 * hash_usage);
#else
  OVH_HASH_PRINT_AGGREGATED_USAGE(file, ofp_phish_target_host_ht_t, PhishTargetHostHashes, work_size, PhishTargetHostHashes + __i, OVH_HASH_STATS);
  OVH_HASH_PRINT_AGGREGATED_USAGE(file, ofp_phish_target_ip_ht_t, PhishTargetIpHashes, work_size, PhishTargetIpHashes + __i, OVH_HASH_STATS);
#endif


  *max_hash_usagePtr = max_hash_usage;
  truncate_log_file(file);
  fclose(file);
}


static void ofp_logger_dump_memory_usage(uint64_t* mem_allocatedPtr, uint64_t* mem_usedPtr, uint32_t* max_mempool_usagePtr)
{
  PRINT_FLOOD("ofp_logger_dump_memory_usage()\n");
  uint64_t mem_allocated = 0;
  uint64_t mem_used = 0;
  uint32_t max_mempool_usage = 0;

  *mem_allocatedPtr = 0;
  *mem_usedPtr = 0;
  *max_mempool_usagePtr = 0;

  FILE* file = open_log_file(OFP_MEMORY_USAGE_LOG_FILE);
  if (file == NULL)
  {
    PRINT_ERR("Failed to open %s\n", OFP_MEMORY_USAGE_LOG_FILE);
    return;
  }

  logger_print_line_separator(file);
  fprintf(file, "Memory pool name                      |  %% used  |   Used   | Allocated |      Used (bytes) | Allocated (bytes)\n");
  logger_print_line_separator(file);

  uint64_t mempool_usage = 0;

  OVH_MEMPOOL_PRINT_USAGE(file, ofp_uri_list_pool, mem_used, mem_allocated, mempool_usage);
  max_mempool_usage = OVH_MAX(max_mempool_usage, mempool_usage);

  OVH_MEMPOOL_PRINT_USAGE(file, ofp_uri_list_entry_pool, mem_used, mem_allocated, mempool_usage);
  max_mempool_usage = OVH_MAX(max_mempool_usage, mempool_usage);

  OVH_MEMPOOL_PRINT_USAGE(file, phish_target_mempool, mem_used, mem_allocated, mempool_usage);
  max_mempool_usage = OVH_MAX(max_mempool_usage, mempool_usage);

  OVH_MEMPOOL_PRINT_USAGE(file, phish_target_ip_mempool, mem_used, mem_allocated, mempool_usage);
  max_mempool_usage = OVH_MAX(max_mempool_usage, mempool_usage);

  OVH_MEMPOOL_PRINT_USAGE(file, event_queue_http_match.mempool, mem_used, mem_allocated, mempool_usage);
  max_mempool_usage = OVH_MAX(max_mempool_usage, mempool_usage);

#if REGEX
  OVH_MEMPOOL_PRINT_USAGE(file, ovh_regex_mempool, mem_used, mem_allocated, mempool_usage);
  max_mempool_usage = OVH_MAX(max_mempool_usage, mempool_usage);
#endif

  truncate_log_file(file);
  fclose(file);

  *mem_allocatedPtr = mem_allocated;
  *mem_usedPtr = mem_used;
  *max_mempool_usagePtr = max_mempool_usage;
}


void* logger(void* arg)
{
  PRINT_D5("logger()\n");
  // Set thread's tile
  if (tmc_cpus_set_my_cpu(tmc_cpus_find_nth_cpu(&normal_cpus, 0)) < 0)
    tmc_task_die("Failure in 'tmc_cpus_set_my_cpu()'.");

  pthread_barrier_wait(work_barrier);
  pthread_barrier_wait(work_barrier);

  PRINT_D5("logger init\n");

  struct timeval now;
  gettimeofday(&now, NULL);
  uint32_t prev_exec = now.tv_sec;
  while(!prgm_exit_requested)
  {
    gettimeofday(&now, NULL);
    while (now.tv_sec == prev_exec)
    {
      usleep(10000);
      gettimeofday(&now, NULL);
    }
    prev_exec = now.tv_sec;

    PRINT_FLOOD("logger loop\n");
    uint64_t startTime = OVH_CUR_TIME_MS;

    uint64_t minBytesIn[work_size], maxBytesIn[work_size], minBytesOut[work_size], maxBytesOut[work_size], prevBytesIn[work_size], prevBytesOut[work_size], minBytesInTotal=0, maxBytesInTotal=0, minBytesOutTotal=0, maxBytesOutTotal=0;
    memset(prevBytesIn, 0, work_size * sizeof(*prevBytesIn));
    memset(prevBytesOut, 0, work_size * sizeof(*prevBytesOut));
    for (int rank = 0; rank < work_size; rank++)
    {
      minBytesIn[rank] = UINT32_MAX;
      maxBytesIn[rank] = 0;
      minBytesOut[rank] = UINT32_MAX;
      maxBytesOut[rank] = 0;
    }
    for (int rank = 0; rank < work_size; rank++)
    {
      uint64_t bytesIn = pkt_stats[rank].bytesIn;
      uint64_t bytesOut = pkt_stats[rank].bytesOut;
      uint64_t bytesInDiff = bytesIn - prevBytesIn[rank];
      uint64_t bytesOutDiff = bytesOut - prevBytesOut[rank];
      if (minBytesIn[rank] > bytesInDiff)
        minBytesIn[rank] = bytesInDiff;
      if (minBytesOut[rank] > bytesOutDiff)
        minBytesOut[rank] = bytesOutDiff;
      if (maxBytesIn[rank] < bytesInDiff)
        maxBytesIn[rank] = bytesInDiff;
      if (maxBytesOut[rank] < bytesOutDiff)
        maxBytesOut[rank] = bytesOutDiff;
      prevBytesIn[rank] = bytesIn;
      prevBytesOut[rank] = bytesOut;
    }
    for (int rank = 0; rank < work_size; rank++)
    {
      minBytesInTotal += minBytesIn[rank];
      maxBytesInTotal += maxBytesIn[rank];
      minBytesOutTotal += minBytesOut[rank];
      maxBytesOutTotal += maxBytesOut[rank];
    }

    FILE *logFile=NULL,
#if (OFP_SYSLOG)
    *syslogFile=NULL,
#endif
#if (OFP_LOOP_STATISTICS)
    *detailsLogFile=NULL,
#endif
    *rawLogFile=NULL;

    PRINT_FLOOD("logger open file %s\n", LOG_FILE);
    logFile = open_log_file(LOG_FILE);
    if (logFile == NULL)
    {
      PRINT_ERR("ERR : could not open %s\n", LOG_FILE);
      continue;
    }

#if (OFP_SYSLOG)
    PRINT_FLOOD("logger open file %s\n", OFP_SYSLOG_FILE);
    syslogFile = open_log_file_append(OFP_SYSLOG_FILE);
    if (syslogFile == NULL)
    {
      PRINT_ERR("ERR : could not open %s\n", OFP_SYSLOG_FILE);
      goto close_log_files;
    }
#endif


#if (OFP_LOOP_STATISTICS)
    PRINT_FLOOD("logger open file %s\n", DETAILS_LOG_FILE);
    detailsLogFile = open_log_file(DETAILS_LOG_FILE);
    if (detailsLogFile == NULL)
    {
      PRINT_ERR("ERR : could not open %s\n", DETAILS_LOG_FILE);
      goto close_log_files;
    }
#endif

    PRINT_FLOOD("logger stats\n");
    // Let's print some stats

    ofp_logger_pkt_stats();

    PRINT_FLOOD("logger ouput stats\n");

    logger_print_line_separator(logFile);
    fprintf(logFile, "Packet actions\n");
    logger_print_line_separator(logFile);

    int char_count = fprintf(logFile, "       Last |      Total | Action/error");
    FPRINTF_SPACE(logFile, CHAR_PER_COLLUMN - char_count);
    fprintf(logFile, "||       Last |      Total | Action/error\n");

    char_count = fprintf(logFile, " %10u | %10u | Forwarded (ICMP)", pkt_stats_prev.forwarded[1], pkt_stats_now.forwarded[1]);
    FPRINTF_SPACE(logFile, CHAR_PER_COLLUMN - char_count);
    fprintf(logFile, "|| %10u | %10u | Forwarded (TCP)\n", pkt_stats_prev.forwarded[6], pkt_stats_now.forwarded[6]);

    char_count = fprintf(logFile, " %10u | %10u | Forwarded (UDP)", pkt_stats_prev.forwarded[17], pkt_stats_now.forwarded[17]);
    FPRINTF_SPACE(logFile, CHAR_PER_COLLUMN - char_count);
    fprintf(logFile, "|| %10u | %10u | Forwarded (Other)\n", pkt_stats_prev.forwarded[0], pkt_stats_now.forwarded[0]);

    char_count = fprintf(logFile, " %10u | %10u | Phish Match", pkt_stats_prev.phishPacketMatch, pkt_stats_now.phishPacketMatch);
    FPRINTF_SPACE(logFile, CHAR_PER_COLLUMN - char_count);
    fprintf(logFile, "|| %10u | %10u | Phish http get\n", pkt_stats_prev.phishPacketHttpGet, pkt_stats_now.phishPacketHttpGet);

    char_count = fprintf(logFile, " %10u | %10u | Phish In", pkt_stats_prev.phishPacketIn, pkt_stats_now.phishPacketIn);
    FPRINTF_SPACE(logFile, CHAR_PER_COLLUMN - char_count);
    fprintf(logFile, "|| %10u | %10u | Phish parsed\n", pkt_stats_prev.phishPacketParsed, pkt_stats_now.phishPacketParsed);

    logger_print_line_separator(logFile);

    int totalCount = 0;
    for(int err=0; err < OFP_ERRORS_MAX_INDEX + 1; err++)
    {
      if (ofp_strerror(-err) != NULL)
      {
        char_count = fprintf(logFile, " %10u | %10u | %s", pkt_stats_prev.errorCodes[err], pkt_stats_now.errorCodes[err], ofp_strerror(-err));
        if ((err % 2) == 0)
        {
          FPRINTF_SPACE(logFile, CHAR_PER_COLLUMN - char_count);
          fprintf(logFile, "||");
        }
        else
          fprintf(logFile, "\n");
        ++totalCount;
      }
    }
    if (totalCount % 2 != 0)
      fprintf(logFile, "\n");

    logger_print_line_separator(logFile);

    PRINT_FLOOD("logger ouput mpipe\n");
#if TILEGX
    memset(&mpipeStats, 0, sizeof(mpipeStats));
    static gxio_mpipe_stats_t prevMpipeStats = {0};
    int get_stats_err = gxio_mpipe_get_stats(mpipe_context, &mpipeStats);
    if(get_stats_err != 0) PRINT_ERR("gxio_mpipe_get_stats() failed : %d\n", get_stats_err);
    logger_print_line_separator(logFile);
    fprintf(logFile, "ingress_packets | ingress_bytes | egress_packets | egress_bytes\n");
    logger_print_line_separator(logFile);
    fprintf(logFile, "%15lu | %13lu | %14lu | %12lu\n", mpipeStats.ingress_packets, mpipeStats.ingress_bytes, mpipeStats.egress_packets, mpipeStats.egress_bytes);
    logger_print_line_separator(logFile);
    fprintf(logFile, "ingress_drops | ingress_drops_no_buf | ingress_drops_ipkt | ingress_drops_cls_lb\n");
    fprintf(logFile, "%13lu | %20lu | %18lu | %18lu\n", mpipeStats.ingress_drops, mpipeStats.ingress_drops_no_buf, mpipeStats.ingress_drops_ipkt, mpipeStats.ingress_drops_cls_lb);
#else // TILEPRO
    // Print netio stats on interfaces
    static uint32_t prevIppReceived = 0;
    static uint32_t prevIppDropped = 0;
    logger_print_line_separator(logFile);
    fprintf(logFile, " Interface | shim drop | shim trunc | ipp received | ipp drop |\n");
    logger_print_line_separator(logFile);
    uint32_t shim;
    netio_get(&queue1, NETIO_PARAM, NETIO_PARAM_OVERFLOW, &shim, sizeof shim);
    netio_stat_t ns;
    netio_get(&queue1, NETIO_PARAM, NETIO_PARAM_STAT, &ns, sizeof ns);
    fprintf(logFile, " %9s | %9u | %10u | %12u | %8u | %8u | %8u | %8u | %8u |\n", interface1, shim&0xFFFF, shim >> 16, ns.packets_received, ns.packets_dropped, ns.drops_no_worker, ns.drops_no_smallbuf, ns.drops_no_largebuf, ns.drops_no_jumbobuf);
#if TWOINTERFACE
    static uint32_t prevIppReceived2 = 0;
    static uint32_t prevIppDropped2 = 0;
    netio_stat_t ns2;
    netio_get(&queue2, NETIO_PARAM, NETIO_PARAM_OVERFLOW, &shim, sizeof shim);
    netio_get(&queue2, NETIO_PARAM, NETIO_PARAM_STAT, &ns2, sizeof ns2);
    fprintf(logFile, " %9s | %9u | %10u | %12u | %8u | %8u | %8u | %8u | %8u |\n", interface2, shim&0xFFFF, shim >> 16, ns2.packets_received, ns2.packets_dropped, ns2.drops_no_worker, ns2.drops_no_smallbuf, ns2.drops_no_largebuf, ns2.drops_no_jumbobuf);
#endif
#endif // /TILEPRO
    logger_print_line_separator(logFile);

#if OFP_SYSLOG
    ofp_event_http_match_log(syslogFile);
#endif


    PRINT_FLOOD("logger ouput loop stats\n");
#if OFP_LOOP_STATISTICS
    // Print loop counts for each worker
    logger_print_line_separator(detailsLogFile);
    fprintf(detailsLogFile, "LOOP COUNTS\n");
    logger_print_line_separator(detailsLogFile);
    fprintf(detailsLogFile, " rank |    Busy    |    Idle    |\n");
    for (int rank=0; rank < work_size; rank++)
    {
      fprintf(detailsLogFile, " %4d | %10u | %10u |\n", rank, loop_counts_busy[rank], loop_counts_idle[rank]);
    }
    logger_print_line_separator(detailsLogFile);

    truncate_log_file(detailsLogFile);
#endif

    float cyclePerPkt = 0.0f;
#if OFP_PROFILING
    PRINT_FLOOD("logger profiling\n");
    logger_print_line_separator(logFile);
    fprintf(logFile, "Cycles in packet_work : %lu\n", *cycles_in_packet_work);
    fprintf(logFile, "Calls to packet_work : %lu\n", *calls_to_packet_work);
    cyclePerPkt = (*calls_to_packet_work) > 0 ? ((float) (*cycles_in_packet_work)) / (*calls_to_packet_work) : 0.0f;
    fprintf(logFile, "cycles/packet_work : %f\n", cyclePerPkt);
    logger_print_line_separator(logFile);

    atomic_and(cycles_in_packet_work, 0);
    atomic_and(calls_to_packet_work, 0);
#endif



    // Memory usage
    uint64_t mem_allocated = 0;
    uint64_t mem_used = 0;
    uint32_t max_mempool_usage = 0;
    ofp_logger_dump_memory_usage(&mem_allocated, &mem_used, &max_mempool_usage);

    uint32_t max_hash_usage = 0;
    ofp_logger_dump_hash_tables_usage(&max_hash_usage);

    logger_print_line_separator(logFile);
    char __buf[32];
    format_human(mem_allocated, __buf);
    fprintf(logFile, "Memory allocated : %s\n", __buf);
    format_human(mem_used, __buf);
    fprintf(logFile, "Memory used :      %s\n", __buf);
    logger_print_line_separator(logFile);

    truncate_log_file(logFile);

    // Store stats for next iteration
    memcpy(&pkt_stats_prev, &pkt_stats_now, sizeof(pkt_stats_now));

    PRINT_FLOOD("logger raw stats\n");
    // Let's print raw stats (no formatting, just CSV)
    // Format :
    //  timestamp;bytes_in_min;bytes_in_avg;bytes_in_max;bytes_out_min;bytes_out_avg;bytes_out_max;ipp_received;ipp_dropped;icmp_packets_forwarded;tcp_packets_forwarded;udp_packets_forwarded;other_packets_forwarded;dropped_for_each_error_code...
    // We're doing log rotation from 0 to 9
    static int rawLogFileIndex = -1;
    char rawLogFilename[20];
    if (rawLogFileIndex < 0)
    {
      // Find the most recent log file
      int i, found = -1;
      uint32_t mostRecentTimestamp = 0;
      char buf[20];
      FILE *rawLogFile = NULL;
      for (i = 0; i <= RAW_LOG_MAX_INDEX; i++)
      {
        sprintf(rawLogFilename, "%s.%d", RAW_LOG_FILE, i);
        rawLogFile = fopen(rawLogFilename, "r");
        if (rawLogFile == NULL)
        {
          // Haven't completed a full rotation yet
          found = i - 1;
          break;
        }
        else
        {
          fread(buf, sizeof(char), 20, rawLogFile);
          uint32_t timestamp = strtoul(buf, NULL, 0);
          if (mostRecentTimestamp == 0)
            mostRecentTimestamp = timestamp;
          else if (timestamp < mostRecentTimestamp)
          {
            found = i - 1;
            break;
          }
        }
        fclose(rawLogFile);
        rawLogFile = NULL;
      }
      if (rawLogFile != NULL)
        fclose(rawLogFile);
      if (found >= 0)
        rawLogFileIndex = found;
      else // No file had more recent data than index 0, we must be at RAW_LOG_MAX_INDEX
        rawLogFileIndex = RAW_LOG_MAX_INDEX;
    }

    sprintf(rawLogFilename, "%s.%d", RAW_LOG_FILE, rawLogFileIndex);
    rawLogFile = fopen(rawLogFilename, "a");
    if (rawLogFile == NULL)
    {
      PRINT_ERR("ERR : could not open %s\n", rawLogFilename);
      goto close_log_files;
    }

    if (ftell(rawLogFile) > RAW_LOG_MAX_FILE_SIZE)
    {
      fclose(rawLogFile);
      rawLogFileIndex++;
      if (rawLogFileIndex > RAW_LOG_MAX_INDEX)
        rawLogFileIndex = 0;
      sprintf(rawLogFilename, "%s.%d", RAW_LOG_FILE, rawLogFileIndex);
      rawLogFile = fopen(rawLogFilename, "w");
      if (rawLogFile == NULL)
      {
        PRINT_ERR("ERR : could not open %s\n", rawLogFilename);
        goto close_log_files;
      }
    }

#define RAW_LOG_MAX_LINE_LEN 500
    struct timeval now;
    gettimeofday(&now, NULL);
     // Timestamp & Bytes in/out (0-6)
#if TILEGX
#define ROW_LOG_FORMAT_START "%ld;%010lu;%010lu;%010lu;%010lu;%010lu;%010lu;"
#else
#define ROW_LOG_FORMAT_START "%ld;%010llu;%010llu;%010llu;%010llu;%010llu;%010llu;"
#endif
    fprintf(rawLogFile, ROW_LOG_FORMAT_START, now.tv_sec, minBytesInTotal, pkt_stats_now.bytesIn / 10, maxBytesInTotal, minBytesOutTotal, pkt_stats_now.bytesOut / 10, maxBytesOutTotal);
#if TILEGX
    fprintf(rawLogFile, "%010lu;%010lu;", mpipeStats.ingress_packets - prevMpipeStats.ingress_packets, mpipeStats.ingress_drops - prevMpipeStats.ingress_drops);
    prevMpipeStats = mpipeStats;
#else // TILEPRO
    // IPP (7-8)
#if TWOINTERFACE
    fprintf(rawLogFile, "%010u;%010u;", (ns.packets_received - prevIppReceived) + (ns2.packets_received - prevIppReceived2), (ns.packets_dropped - prevIppDropped) + (ns2.packets_dropped - prevIppDropped2));
    prevIppReceived2 = ns2.packets_received;
    prevIppDropped2 = ns2.packets_dropped;
#else
    fprintf(rawLogFile, "%010u;%010u;", ns.packets_received - prevIppReceived, ns.packets_dropped - prevIppDropped);
#endif
    prevIppReceived = ns.packets_received;
    prevIppDropped = ns.packets_dropped;
#endif // /TILEPRO
    // pkt stats (9-25)
    fprintf(rawLogFile, "%010u;", pkt_stats_now.forwarded[1]);
    fprintf(rawLogFile, "%010u;", pkt_stats_now.forwarded[6]);
    fprintf(rawLogFile, "%010u;", pkt_stats_now.forwarded[17]);
    fprintf(rawLogFile, "%010u;", pkt_stats_now.forwarded[0]);
    for(int err=0; err < OFP_ERRORS_MAX_INDEX + 1; err++)
    {
      fprintf(rawLogFile, "%010u;", pkt_stats_now.errorCodes[err]);
    }

    // Memory usage in kB (26-27)
    fprintf(rawLogFile, "%010u;", (uint32_t) mem_used / 1024);
    fprintf(rawLogFile, "%010u;", (uint32_t) mem_allocated / 1024);
    // (28-30)
    fprintf(rawLogFile, "%010u;", 0);
    fprintf(rawLogFile, "%010u;", 0);
    fprintf(rawLogFile, "%010u;", 0);
    fprintf(rawLogFile, "\n");

    send_stats_udp(now.tv_sec, max_mempool_usage, max_hash_usage, cyclePerPkt);

    PRINT_FLOOD("logger reset stats\n");
    // Let's reset stats
    for (int rank=0; rank < work_size; rank++)
    {
      atomic_and(&(pkt_stats[rank].bytesIn), 0);
      atomic_and(&(pkt_stats[rank].bytesOut), 0);
      atomic_and(&(pkt_stats[rank].bytesBadIp), 0);
      atomic_and(&(pkt_stats[rank].bytesParsed), 0);
      atomic_and(&(pkt_stats[rank].phishPacketMatch), 0);
      atomic_and(&(pkt_stats[rank].phishPacketIn), 0);
      atomic_and(&(pkt_stats[rank].phishPacketParsed), 0);
      atomic_and(&(pkt_stats[rank].phishPacketHttpGet), 0);
      atomic_and(&(pkt_stats[rank].loopCount), 0);
      for (int proto = 0; proto <= 0xFF; proto++)
      {
        atomic_and(&(pkt_stats[rank].forwarded[proto]), 0);
      }
      for(int err=0; err < OFP_ERRORS_MAX_INDEX + 1; err++)
      {
        atomic_and(&(pkt_stats[rank].errorCodes[err]), 0);
      }
    }

close_log_files:
    PRINT_FLOOD("closing files\n");
    if (logFile != NULL)
      fclose(logFile);
#if (OFP_SYSLOG)
    if (syslogFile != NULL)
      fclose(syslogFile);
#endif
#if (OFP_LOOP_STATISTICS)
    if (detailsLogFile != NULL)
      fclose(detailsLogFile);
#endif
    if (rawLogFile != NULL)
      fclose(rawLogFile);

    // Adapt the sleep time to the function execution time
    uint64_t elapsedTime = (OVH_CUR_TIME_MS) - startTime;

    logger_loop_duration_ms = elapsedTime;

  }
  PRINT_FLOOD("logger() returns\n");

  return NULL;
}



/*
 * ofp_logger_init
 *
 * Allocate the loop counter stats
 * Allocate the load average stat
 * Allocate the network stats
 */
void ofp_logger_init(tmc_alloc_t* alloc)
{
  PRINT_D5("Allocating shared memory...\n");
  // Allocate data in shared memory
  pkt_stats = tmc_alloc_map (alloc, sizeof(pkt_stats_s) * work_size);
  memset(pkt_stats, 0, sizeof(pkt_stats_s) * work_size);

#if OFP_LOOP_STATISTICS
  // Init loopCounts arrays
  loop_counts_busy = (uint32_t*) tmc_alloc_map (alloc, sizeof(uint32_t) * work_size);
  memset(loop_counts_busy, 0, sizeof(uint32_t) * work_size);
  loop_counts_idle = (uint32_t*) tmc_alloc_map (alloc, sizeof(uint32_t) * work_size);
  memset(loop_counts_idle, 0, sizeof(uint32_t) * work_size);
#endif

#if OFP_PROFILING
  cycles_in_packet_work =  tmc_alloc_map (alloc, sizeof(*cycles_in_packet_work));
  calls_to_packet_work = tmc_alloc_map (alloc, sizeof(*calls_to_packet_work));
#endif
}
