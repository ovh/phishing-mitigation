#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#if TILEGX
#include <gxio/mpipe.h>
#include <arch/cycle.h>
#else
#include <netio/netio.h>
#endif
#include <tmc/alloc.h>
#include <tmc/cpus.h>
#include <tmc/sync.h>
#include <tmc/spin.h>
#include <tmc/task.h>
// So we can backtrace if we segfault
#include <signal.h>
#include <execinfo.h>

#include <pthread.h>

#include <sys/time.h>
#include <sys/wait.h>

#define OFP_MAIN
#include "ofp.h"
#include "ofp_netio.h"
#include "ofp_phish.h"
#include "ofp_config.h"
#include "ofp_logger.h"
#include "ofp_gc.h"
#include "ofp_init.h"
#include "ofp_socket.h"
#include "ofp_socket_message_cb.h"

#define MAX_ADDITIONAL_PACKET_CAPACITY 10

int packet_drop;
#if TMC
#if MODE_VLAN
int packet_vlan_swap;
uint16_t packet_vlan_swap1;
uint16_t packet_vlan_swap2;
#endif //MODE_VLAN
#endif //TMC

//-------------------------------------------------------------------------------------------
// SIGSEGV handler
//-------------------------------------------------------------------------------------------
void segv_handler(int sig)
{
  fprintf(stderr, "segv_handler() callback called with signal %d:\n", sig);
  log_backtrace();
  raise(SIGINT);
  exit(1);
}
//-------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------
// SIGTERM handler
//-------------------------------------------------------------------------------------------
void sigterm_handler(int sig)
{
  fprintf(stderr, "sigterm_handler() callback called with signal %d:\n", sig);
#if SOCKET
  socket_stop();
#endif
  signal(SIGTERM, SIG_DFL);
  exit(SIGTERM);
}
//-------------------------------------------------------------------------------------------

// On TileGX, the GC can use the workers' equeues
#if !TILEGX
static NETIO_EQUEUE_T gc_queue1;
#if TWOINTERFACE
static NETIO_EQUEUE_T gc_queue2;
#endif
#endif

#include "ofp_ipv4.h"
#include "ofp_tcp.h"
#include "ofp_packet_list.h"

//=======================================================================================================
// Here we store some data on the netio_pkt_t currently being processed, for each worker
//=======================================================================================================
typedef struct
{
  uint32_t ipDest; // In network byte-order
//  uint32_t ipSrc; // In network byte-order
} pkt_info;

static pkt_info *cur_pkt_info = NULL;
//=======================================================================================================

//=======================================================================================================
// Global variables in shared memory (shared between processes)
//=======================================================================================================

#if OFP_LOOP_STATISTICS
uint32_t *loop_counts_busy = NULL;
uint32_t *loop_counts_idle = NULL;
#endif
//=======================================================================================================

//=======================================================================================================
// PCAP Dumping
//=======================================================================================================
#include "ofp_pcap.h"

//=======================================================================================================

#if DEBUG == 1
// Used to count/print smthg if we receive ipv6 packets
uint16_t nbIpv6Packets = 0;
#endif

static INLINE int packet_work_l4(const int work_rank, netio_pkt_t *packet, PacketList* additionalPackets)
{
  netio_pkt_metadata_t *mda = NETIO_PKT_METADATA(packet);
  uint8_t* l3Header = (uint8_t*)NETIO_PKT_L3_DATA_M(mda, packet);
  int sendIt = 1;

  // max 0xFF (8-bit), store it in 32bits for performance
  uint32_t protocol = *(l3Header + 9);
  switch (protocol)
  {
    case OFP_IPV4_PROTO_TCP: // TCP
      sendIt = ofp_tcp_check_packet(packet, mda);
      if (sendIt == 1)
      {
        phish_packet_work(work_rank, packet, mda, &sendIt, additionalPackets);
      }
      break;
    default:
      PRINT_D5("packet is not a protocol we handle : %02x\n", protocol);
      break;
  }
  if (sendIt > 0)
    sendIt = protocol;
  return sendIt;
}

#if OFP_PROFILING
uint64_t *cycles_in_packet_work = 0;
uint64_t *calls_to_packet_work = 0;
#endif

// Process a packet.
//
static INLINE int packet_work(const int work_rank, netio_pkt_t *packet, netio_pkt_metadata_t *mda, PacketList* additionalPackets)
{
  uint16_t *etherType = (uint16_t*)NETIO_PKT_L2_DATA_M(mda, packet);

  int offset = 0;
#if MODE_VLAN
  offset = 2;
#endif
  // Forward by default
  int sendIt = 0xFF;
  if ( *(etherType + offset + 6) == 0x0008)  // ipv4
  {
    uint8_t* l3Header = (uint8_t*)NETIO_PKT_L3_DATA_M(mda, packet);
    netio_pkt_inv(l3Header, 20);

    // TODO have the functions below reuse what we put in cur_pkt_info
    cur_pkt_info[work_rank].ipDest = *(uint32_t*) (l3Header + OFP_IPV4_OFFSET_IP_DEST);
//    cur_pkt_info[work_rank].ipSrc = *(uint32_t*) (l3Header + OFP_IPV4_OFFSET_IP_SRC);

    sendIt = ofp_ipv4_check_packet(mda, packet, l3Header);
    if (sendIt == 1)
    {
      // Don't check fragments, unless it's the first one
      const uint16_t fragment_flags_offset = *(uint16_t*) (l3Header + 6);
      if ( ! (fragment_flags_offset & 0x0020) || ! (fragment_flags_offset & 0xFF1F))
        sendIt = packet_work_l4(work_rank, packet, additionalPackets);
    }
  }
  else if( *(etherType + offset + 6) == 0xdd86)  // ipv6
  {
#if DEBUG == 1
    if (  ! ( nbIpv6Packets++ % 2048)){
            printf("6");
    }
#endif
    PRINT_D5("packet is IPv6\n");
  }
  else
  {
    PRINT_D5("packet is not ipv4 : %02x\n", *(etherType + offset + 6));
  }
#if MODE_VLAN
  if (sendIt > 0 && packet_vlan_swap && !packet_drop)
  {
    PRINT_D5("Going to swap VLANs because sendIt=%d, packet_vlan_swap=%d & packet_drop=%d\n", sendIt, packet_vlan_swap, packet_drop);
    ofp_netio_packet_swap_vlan(work_rank, etherType, &sendIt);
  }
#endif
  return sendIt;
}

//========================================
// Main loop suitable for load testing.
// This runs until some packets have been received and then
// a fixed idle time has passed.

#if OFP_LOOP_STATISTICS
// Exit after some number of packets
unsigned limit_packets = 0;

// Post-traffic idle time.
static unsigned limit_idle = 0;
#endif

// Loop processing packets
// We keep a two-packet pipeline, with an old packet outgoing
// and a new packet incoming.
// A deeper pipeline can improve performance with some code complexity
//

static void loop(const int work_rank)
{
  // INGRESS QUEUES
  NETIO_IQUEUE_T* queueSwitchA = queues1[work_rank];
#if TILEGX
#define QUEUE_TAG_A queueSwitchA
#define QUEUE_TAG_B queueSwitchA
#else // TILEPRO
#if TWOINTERFACE
  NETIO_IQUEUE_T* queueSwitchB = queues2[work_rank];;
  NETIO_IQUEUE_T* queueSwitchTemp;
#define QUEUE_TAG_A queueSwitchA
#define QUEUE_TAG_B queueSwitchB
#else
#define QUEUE_TAG_A queueSwitchA
#define QUEUE_TAG_B queueSwitchA
#endif
#endif // /TILEPRO

#if TILEGX
  // EGRESS QUEUES
  NETIO_EQUEUE_T **equeues = equeuesW[work_rank % max_equeues];
#endif

#if OFP_LOOP_STATISTICS
  // Loop duration from first arrival to last departure.
  unsigned long long first_time = 0, last_time = 0;
  // Loop statstics
  unsigned long long loop_packets = 0;
  unsigned long long loop_bytes = 0;
  uint32_t loopCountBusy = 0;
  uint32_t loopCountIdle = 0;
#endif

#if (DEBUG == 1 )
        uint16_t lastDidNotWorkSomething = 0 ;
#endif

  PacketList* additionalPackets = PacketListNew(MAX_ADDITIONAL_PACKET_CAPACITY);
  pkt_stats_s* pkt_stat = &pkt_stats[work_rank];

  while (1)
  {
    pkt_stat->loopCount++;

    PacketListClear(additionalPackets);

#if TWOINTERFACE && !TILEGX
        queueSwitchTemp=queueSwitchA;
        queueSwitchA=queueSwitchB;
        queueSwitchB=queueSwitchTemp;
#endif
//          printf("worker %d/%d , new loop\n", work_rank, work_size);
    // Current iteration

    // New packet arrival.
    int packet_valid = 0;
    int packet_sendIt = 0;
    unsigned packet_size = 0;

#if OFP_LOOP_STATISTICS
    unsigned long long loop_time = get_cycle_count();
    // Check for clean loop exit.
    //
    if ((limit_packets != 0) && (loop_packets == limit_packets))
      break;
    if ((loop_packets != 0) && (limit_idle != 0) &&
        (last_time + limit_idle <= loop_time))
      break;
#endif

    // Arrivals.
 //         printf("worker %d/%d , pull a packet\n", work_rank, work_size);
 //TODO On TileGX, get multiple packets at once
#if TILEGX
    gxio_mpipe_idesc_t *idescs;
    packet_valid = ofp_netio_packet_pull(QUEUE_TAG_A, &idescs);
#else // TILEPRO
    netio_pkt_t packet;
    packet_valid = ofp_netio_packet_pull(QUEUE_TAG_A, &packet);
#endif
 //         printf("worker %d/%d , pulled a packet with return %d \n", work_rank, work_size,packet_valid);
    if (packet_valid == 1)
    {
#if OFP_PROFILING
      uint32_t cycles_before = get_cycle_count();
#endif
#if TILEGX
      netio_pkt_t packet = *idescs;
      gxio_mpipe_edesc_t edescs[8];
      gxio_mpipe_edesc_copy_idesc(&edescs[0], &packet);
#endif
#if OFP_LOOP_STATISTICS
      last_time = loop_time;
      if (first_time == 0)
        first_time = loop_time;
#endif

#if (DEBUG == 1 )
      lastDidNotWorkSomething=0;
#endif
      netio_pkt_metadata_t *mda = NETIO_PKT_METADATA(&packet);

      PRINT_D5("worker %d/%d , got a packet with channel %d[#%d] (config_bridge_mode = %d)\n", work_rank, work_size, packet.channel, ofp_netio_channel_to_index(packet.channel), config_bridge_mode);

      packet_size = NETIO_PKT_L2_LENGTH_M(mda, &packet);
      pkt_stats[work_rank].bytesIn += packet_size;

      // On which equeue should we send the packet ?
#if TILEGX

#else // TILEPRO
#if MODE_VLAN
  NETIO_EQUEUE_T *equeue = QUEUE_TAG_B;
#else
  NETIO_EQUEUE_T *equeue = QUEUE_TAG_A;
#endif
#endif // /TILEPRO

  packet_sendIt = packet_work(work_rank, &packet, mda, additionalPackets);

  ofp_netio_additional_packet_push(work_rank, equeues, additionalPackets);

#if MODE_VLAN
  TODO
#else
  NETIO_EQUEUE_T *equeue = ofp_netio_get_equeue_from_channel(equeues, packet.channel);
#endif

  int pcap_dump = 0;

  const uint32_t destIpLastByte = cur_pkt_info[work_rank].ipDest >> 24;
  const uint64_t bitmapLastByte = pcap_dump_ips_last_byte[destIpLastByte / 64];
  if (bitmapLastByte)
  {
    const uint32_t remIpLastByte = destIpLastByte & 63;
    if (bitmapLastByte & pcap_dump_ips_bit_masks[remIpLastByte])
    {
      const uint64_t block = pcap_dump_ips[(cur_pkt_info[work_rank].ipDest & 0xFFFFFF) / 64];
      if (block)
      {
        const uint32_t remIp = cur_pkt_info[work_rank].ipDest & 63;
        if (block & pcap_dump_ips_bit_masks[remIp] )
        {
          // Tell the mpipe we will release the buffer ourselves
          edescs[0].hwb = 0;

          pcap_dump = 1;
        }
      }
    }
  }


#if TILEGX
    ofp_netio_packet_push(work_rank, QUEUE_TAG_A, equeue, &packet, &edescs[0], packet_size, packet_sendIt);
#else // TILEPRO
#if MODE_VLAN
if (packet_sendIt <= 0)
      ofp_netio_packet_push(work_rank, QUEUE_TAG_A, equeue, &packet, packet_size, packet_sendIt);
else
      ofp_netio_packet_push(work_rank, QUEUE_TAG_B, equeue, &packet, packet_size, packet_sendIt);
#else
    ofp_netio_packet_push(work_rank, QUEUE_TAG_A, equeue, &packet, packet_size, packet_sendIt);
#endif
#endif

    if (pcap_dump)
    {
      ofp_pcap_dump_request request;
      request.ip = cur_pkt_info[work_rank].ipDest;
      request.packetSendIt = packet_sendIt;
      request.packetLength = NETIO_PKT_L2_LENGTH_M(mda, &packet);
      request.buffer = (void *)((uintptr_t)(packet.va));
      request.stackId = packet.stack_idx;
      ofp_pcap_dump_request_push(&request, work_rank);
    }

    gxio_mpipe_iqueue_consume(QUEUE_TAG_A, &packet);

#if OFP_LOOP_STATISTICS
      loop_packets++;
      loop_bytes += packet_size;
      if (  ! (loopCountBusy++ % 1024)) {
        loop_counts_busy[work_rank]++;
      }
#endif
      // Reset pkt_info
      cur_pkt_info[work_rank].ipDest = 0;

#if OFP_PROFILING
  uint32_t cycles_after = get_cycle_count();
  atomic_add(cycles_in_packet_work, cycles_after - cycles_before);
  atomic_increment(calls_to_packet_work);
#endif
    }
    else
    {
#if (DEBUG == 1 )
      if (  ! ( lastDidNotWorkSomething++ %2048)){
              printf(" ");
      }
#endif
#if OFP_LOOP_STATISTICS
      if (  ! (loopCountIdle++ % 1024)) {
        loop_counts_idle[work_rank]++;
      }
#endif
    }
  }

#if OFP_LOOP_STATISTICS
  // Summarize.
  printf("worker %d\t packets %lld\t bytes %lld\tcycles %lld\n",
         work_rank, loop_packets, loop_bytes, last_time-first_time);
#endif
}

// Set to 1 when all workers have been initialized and will start looping on packet
static int workers_started = 0;

static void* worker(void* arg)
{
  int rank = (long) arg;

  ofp_tcp_init_thread();

  // Set thread's tile according to its rank
  int cpu = tmc_cpus_find_nth_cpu(&dataplane_cpus, rank);
  if (tmc_cpus_set_my_cpu(cpu) < 0)
    tmc_task_die("Failure in 'tmc_cpus_set_my_cpu()'.");

#if TILEGX
  if (rank == 0)
  {
    ofp_mpipe_init();
    pthread_barrier_wait(work_barrier);
  }
  else
  {
    pthread_barrier_wait(work_barrier);
  }
  // One more wait to match how many we have in TILEPRO mode...
  pthread_barrier_wait(work_barrier);

#else // TILEPRO
  // Configure flow hashing
  NETIO_IQUEUE_T *queue1 = queues1[rank];
#if TWOINTERFACE
  NETIO_IQUEUE_T *queue2 = queues2[rank];
#endif
  // Configure one queue to each worker.
  //
  ofp_netio_queue_config(rank, queue1, rank,interface1, 1);
#if TWOINTERFACE
  ofp_netio_queue_config(rank, queue2, rank,interface2, 1);
#endif

  // Only one worker configures the flow
  //
  if (rank == 0)
  {
    netio_group_t flowtbl1;
    ofp_netio_flow_config(queue1, &flowtbl1, 0, work_size);
    ofp_netio_group_config(queue1, &flowtbl1, 0, 0x1000);

#if TWOINTERFACE
    netio_group_t flowtbl2;
    ofp_netio_flow_config(queue2, &flowtbl2, 0, work_size);
    ofp_netio_group_config(queue2, &flowtbl2, 0, 0x1000);
#endif
  }
  //
  // Wait for all of the threads to be ready to process packets.
  //
  pthread_barrier_wait(work_barrier);
  if (rank == 0)
  {
    netio_input_initialize(queue1);
#if TWOINTERFACE
    netio_input_initialize(queue2);
#endif
    pthread_barrier_wait(work_barrier);
  }
  else
  {
    // Wait for thread 0 to have called netio_input_initialize
    pthread_barrier_wait(work_barrier);
  }
#endif // /TILEPRO

  // OK. All set to go.
  //
  if (rank == 0)
  {
    workers_started = 1;
    gettimeofday(&ovh_global_cur_time, NULL);
    PRINT_INFO("Init done, starting main loop\n");
  }
  loop(rank);
  PRINT_ERR("WORKER STOPPED LOOPING\n");
  return NULL;
}

/*
static int
time_sort(tcp_whitelist_data *a, tcp_whitelist_data *b)
{
  return timercmp(&a->lastPacketTime, &b->lastPacketTime, >);
}
*/

#include <sys/socket.h>
#include <arpa/inet.h>


static void reload_conf(int sig);

// This arranges the environment so that we have 'count' threads,
// each bound to a single CPU and assigned an integer rank between 0
// and (count - 1).
//
static void go_parallel(int count)
{
  ofp_tcp_init(count);
  ofp_pcap_init();

  cur_pkt_info = OVH_CALLOC(count, sizeof(pkt_info));

  // Init queues arrays
  queues1 = (NETIO_IQUEUE_T**) OVH_MALLOC(sizeof(NETIO_IQUEUE_T*) * work_size);
  for (int i = 0; i < work_size; i++)
  {
    queues1[i] = OVH_CALLOC(1, sizeof(NETIO_IQUEUE_T));
  }
#if TWOINTERFACE
#if !TILEGX
  queues2 = (NETIO_IQUEUE_T**) OVH_MALLOC(sizeof(NETIO_IQUEUE_T*) * work_size);
  for (int i = 0; i < work_size; i++)
  {
    queues2[i] = OVH_CALLOC(1, sizeof(NETIO_IQUEUE_T));
  }
#endif
#endif

#if !TILEGX
  equeues1 = queues1;
#if TWOINTERFACE
  equeues2 = queues2;
#endif
#endif

  // Block SIGUSR1 signals in other threads, we want this thread to handle them
  // We set the blocking mask here, it will be inherited by threads created below
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  if (pthread_sigmask(SIG_BLOCK, &set, NULL))
    tmc_task_die("pthread_sigmask BLOCK failed\n");

  pthread_t thread[count];
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  for (long rank = 0; rank < count; rank++)
  {
    if (pthread_create(&thread[rank], NULL, worker, (void*) rank))
      tmc_task_die("pthread_create failed for worker %ld", rank);
  }

#if SOCKET
  // Start socket listen thread
  socket_start(ofp_socket_message_cb, NULL);
#endif

  // Create GC thread
  pthread_t gcThread;
  if (pthread_create(&gcThread, NULL, garbage_collector, NULL))
        tmc_task_die("pthread_create failed for garbage_collector.");

  // Create Logger thread
  pthread_t loggerThread;
  if (pthread_create(&loggerThread, NULL, logger, NULL))
        tmc_task_die("pthread_create failed for logger.");

  // All threads started
  pthread_barrier_wait(work_barrier);
  pthread_barrier_wait(work_barrier);
  // Ok, everything is ready, start receiving packets
  ofp_mpipe_start();

  pthread_attr_destroy(&attr);
  // Unblock SIGUSR1
  if (pthread_sigmask(SIG_UNBLOCK, &set, NULL))
    tmc_task_die("pthread_sigmask UNBLOCK failed\n");


  // Wait for worker threads to return
  int rc;
  void* status;
  for (long rank = 0; rank < count; rank++)
  {
    rc = pthread_join(thread[rank], &status);
    if (rc)
    {
      tmc_task_die("ERROR; return code from pthread_join() is %d\n", rc);
    }
    PRINT_D2(" Completed join with thread %ld having a status of %ld\n", rank, (long)status);
  }

  PRINT_D2("prgm_exit_requested\n");
  // Workers have ended, ask other threads to stop
  prgm_exit_requested = 1;
#if MODE_FIREWALL
  // Wait for the GC thread to stop
  rc = pthread_join(gcThread, &status);
  if (rc)
    tmc_task_die("ERROR joining GC thread; return code from pthread_join() is %d\n", rc);
#endif

  return;
}



/* Callback to catch SIGUSR1
usage : pkill -SIGUSR1 tilera-phishing -n
*/
static void reload_conf(int sig)
{
  PRINT_D5("received reload_conf() signal\n");
  parse_configuration_file(1);
}




int main(int argc, char** argv)
{
  // Disable buffering on stdout
  setbuf(stdout, NULL);

// Init default values for global variables
  work_size = 1;
  packet_drop = 0;
#if TILEGX
  nb_interfaces = 2;
  interfaces = OVH_CALLOC(2, sizeof(char*));
  interfaces[0] = "xgbe1";
  interfaces[1] = "xgbe2";
#else
  interface1 = "xgbe/0";
  interface2 = "xgbe/1";
#endif
#if MODE_VLAN
  packet_vlan_swap = 1;
  packet_vlan_swap1 = 0x4e00;
  packet_vlan_swap2 = 0x3200;
#endif

  gettimeofday(&ovh_global_cur_time, NULL);

  parse_configuration_args(argc, argv);

  if (config_daemonize)
  {
    // In daemon mode, redirect stdout & stderr to log file OFP_STD_LOG
    freopen(OFP_STD_LOG, "a", stdout);
    dup2(fileno(stdout), fileno(stderr));
    // No buffering thank you very much
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
  }
  ofp_log_startup();

  parse_configuration_file(0);

  ovh_cpu_init(work_size);

  if (config_daemonize)
  {
    PRINT_D5("daemonizing...\n");
    if (daemon(0, 1))
      tmc_task_die("Failed to daemonize");
  }

//#if DEBUG <= 0
  PRINT_D5("Installing SIGSEGV...\n");
  // Install SIGSEGV handler
  signal(SIGSEGV, segv_handler);
//#endif

//#if DEBUG <= 0
  PRINT_D5("Installing SIGTERM...\n");
  // Install SIGTERM handler
  signal(SIGTERM, sigterm_handler);
//#endif

  if (config_daemonize)
  {
    PRINT_D5("forking...\n");
    // Let's fork, and have the parent watch over the child and restart it if it crashes
    pid_t pid = fork();
    if (pid < 0)
      tmc_task_die("Failed to fork !\n");
    while (pid > 0)
    {
      int status = 0;
      if (waitpid(pid, &status, 0) == pid)
      {
        time_t now;
        time(&now);
        fprintf(stderr, "Child process stopped (crashed ?) at %s, restarting...\n", ctime(&now));
        sleep(1);
        pid = fork();
        if (pid < 0)
          tmc_task_die("Failed to fork !\n");
      }
      else
      {
        tmc_task_die("Error on waitpid !\n");
      }
    }
  }

  gettimeofday(&ovh_global_cur_time, NULL);

  PRINT_D5("Allocating a 'barrier'...\n");
  // Allocate a "barrier" in memory which will be shared between the
  // worker threads
  tmc_alloc_t alloc = TMC_ALLOC_INIT;
  tmc_alloc_set_shared(&alloc);
  work_barrier = (pthread_barrier_t*)tmc_alloc_map(&alloc, sizeof(*work_barrier));
  if (work_barrier == NULL)
    tmc_task_die("Failed to allocate memory for barrier.");
  int barrier_count = work_size + 1 /*GC*/ + 1 /* Logger*/ + 1 /* Main */;
#if SOCKET
  barrier_count += 1; /* Socket */
#endif
  pthread_barrier_init(work_barrier, NULL, barrier_count );

  ofp_logger_init(&alloc);

  ofp_init(work_size, 0);
  ofp_init_alloc_shared(&alloc);
  parse_ip_configuration_file(0);

  PRINT_D5("Installing SIGUSR1\n");
  // Install SIGUSR1 handler
  signal(SIGUSR1, reload_conf);

  gettimeofday(&ovh_global_cur_time, NULL);

  PRINT_D5("go_parallel()\n");
  // Start worker threads
  go_parallel(work_size);

  PRINT_D5("exiting...\n");
  pthread_exit(NULL);

}

