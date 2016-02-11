#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <tmc/task.h>
#include <tmc/alloc.h>
#include <tmc/cpus.h>
#include <pthread.h>

#include "ofp.h"
#include "ofp_main.h"
#include "ofp_gc.h"
#include "ofp_pcap.h"
#include "ofp_ipv4.h"
#include "ofp_netio.h"
#include "ofp_phish.h"

#define MSEC_BETWEEN_GC_EXECS 10
#define SEC_BETWEEN_WHITELIST_CLEANUP 60 * 60
#define LOOPCOUNT_BETWEEN_WHITELIST_CLEANUP (SEC_BETWEEN_WHITELIST_CLEANUP * 1000 / MSEC_BETWEEN_GC_EXECS)

// ------------------------------
// Read-write lock for garbage_collector & logger
// Since garbage_collector is the only one freeing data from hashes,
// we only need a lock between the GC and the logger to ensure that the logger will not access freed data
// ------------------------------
pthread_mutex_t mutex_gc = PTHREAD_MUTEX_INITIALIZER;


#define IP_DUMP_FILE "/etc/tilera-phishing/dump.ips"
static void parse_ip_dump_file(int closeFiles)
{
  FILE *dumpFile = fopen(IP_DUMP_FILE, "r");
  if (dumpFile == NULL)
  {
    PRINT_ERR("Could not load " IP_DUMP_FILE "\n");
    return;
  }

  // Let's empty the pcap dump hash and close current dump files
  ofp_pcap_refresh_dumps(closeFiles);

  char * line = NULL;
  size_t len = 0;
  ssize_t read;

  while ((read = getline(&line, &len, dumpFile)) != -1) {
    // Ignore empty lines and lines starting with '#'
    if (strcmp(line, "\n") == 0 || line[0] == '#')
      continue;
    // Duplicate line since strtok modifies its arg
    char *dup_line = strdup(line);
    char *saveptr;
    char *ip = strtok_r(dup_line, ";\n", &saveptr);

    ip_port_tuple ip_port;
    uint32_t pcap_dump_dest_ip = 0;
    if (parse_ip(ip, 1, &ip_port))
    {
      pcap_dump_dest_ip = ip_port.port;
      // Parse options for the dump
      // What packets should we dump (based on 'sendIt' code) ?
      char *value = strtok_r(NULL, ";\n", &saveptr);
      int code = 0;
      if (value)
      {
        code = atoi(value);
      }
      pcap_dump_ips[(pcap_dump_dest_ip & 0xFFFFFF) / 64] |= pcap_dump_ips_bit_masks[pcap_dump_dest_ip & 63];
      uint32_t destIpLastByte = pcap_dump_dest_ip >> 24;
      pcap_dump_ips_last_byte[destIpLastByte / 64] |= pcap_dump_ips_bit_masks[destIpLastByte & 63];

      pcap_dump_hash_add_ip(pcap_dump_dest_ip, strdup(ip), code, closeFiles);
    }

    OVH_FREE(dup_line);
  }

  if (line != NULL)
    OVH_FREE(line);

  fclose(dumpFile);

  ofp_pcap_cleanup_hash(pcap_dump_clear_bit);
}

void* garbage_collector(void* arg)
{
  // Set thread's tile
  if (tmc_cpus_set_my_cpu(tmc_cpus_find_nth_cpu(&dataplane_cpus, work_size)) < 0)
    tmc_task_die("Failure in 'tmc_cpus_set_my_cpu()'.");

#if !TILEGX
  ofp_netio_queue_config(work_size, &gc_queue1, work_size, interface1, 0);
#if TWOINTERFACE
  ofp_netio_queue_config(work_size, &gc_queue2, work_size, interface2, 0);
#endif
#endif
  pthread_barrier_wait(work_barrier);
  pthread_barrier_wait(work_barrier);

  PRINT_D5("[GC] Starting\n");
  uint8_t gcContinue = 1;

  struct timeval prev_gc_exec;
  struct timeval prev_pcap_dump_refresh;
  struct timeval prev_pcap_files_close;

  gettimeofday(&prev_pcap_dump_refresh, NULL);
  gettimeofday(&prev_pcap_files_close, NULL);
  OVH_UPDATE_CUR_TIME();

  while(gcContinue)
  {
    phish_sync();

    gettimeofday(&prev_gc_exec, NULL);
    OVH_UPDATE_CUR_TIME();
    pthread_mutex_lock(&mutex_gc);
    //PRINT_D5("[GC] Execution\n");

#if MOD_PHISH_LOGGER
    ofp_phish_logger_cleanup(work_size);
#endif

    pthread_mutex_unlock(&mutex_gc);
    gettimeofday(&ovh_global_cur_time, NULL);
    int i = 0;
    while (timevaldiff_msec(&prev_gc_exec, &ovh_global_cur_time) < MSEC_BETWEEN_GC_EXECS)
    {
      ofp_pcap_check_and_dump();
      if (i++ % 10 == 0)
      {
        gettimeofday(&ovh_global_cur_time, NULL);
      }
    }
    // Should we continue ?
    if (prgm_exit_requested)
    {
      gcContinue = 0;
    }
    if ( ovh_global_cur_time.tv_sec % PCAP_SECONDS_PER_FILE == 0 && ovh_global_cur_time.tv_sec != prev_pcap_dump_refresh.tv_sec)
    {
      int closePcapFiles = ovh_global_cur_time.tv_sec - prev_pcap_files_close.tv_sec >= 60;
      parse_ip_dump_file(closePcapFiles);
      prev_pcap_dump_refresh = ovh_global_cur_time;
      if (closePcapFiles)
      {
        prev_pcap_files_close = ovh_global_cur_time;
      }
    }
  }
  PRINT_D2("[GC] Stoping\n");
  return NULL;
}
