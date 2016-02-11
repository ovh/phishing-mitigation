#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <tmc/task.h>
#include <tmc/alloc.h>
#include <tmc/cpus.h>

#include "ofp.h"
#include "ofp_netio.h"
#include "ofp_pcap.h"

#if TILEGX
gxio_mpipe_context_t *mpipe_context;

char** interfaces;
// Array containing the channel numbers for each link we handle
#else //TILEPRO
char *interface1;
char *interface2;
#endif

// Netio queues of each worker
NETIO_IQUEUE_T **queues1;
#if TILEGX
// On Gx, we can have simply have on iqueue per worker, for any number of links.
// We do need one equeue per link.
// We then use the 'channel' field in gxio_mpipe_idesc_t to figure out where to egress the packet
// Thus, we build a 2D array : equeuesW[worker_rank % max_equeues][channel]
NETIO_EQUEUE_T ***equeuesW;
// Max. equeues per link
int max_equeues;
int stack_idx_small_buf;
int stack_idx_large_buf;
#else // TILEPRO
NETIO_EQUEUE_T **equeues1;
#if TWOINTERFACE
NETIO_IQUEUE_T **queues2;
NETIO_EQUEUE_T **equeues2;
#endif
#endif // /TILEPRO

#if TILEGX

// The number of entries in the equeue ring.
static unsigned int equeue_entries = 2048;

static void create_stack(gxio_mpipe_context_t* context, int stack_idx, gxio_mpipe_buffer_size_enum_t buf_size, int num_buffers);

static int bucket = 0;
static int num_buckets = 1024;

void ofp_mpipe_init()
{

  PRINT_INFO("ofp_mpipe_init()\n");
  PRINT_INFO("nb_interfaces = %d\n", nb_interfaces);

  int result;
  mpipe_context = OVH_CALLOC(1, sizeof(*mpipe_context));
  gxio_mpipe_context_t* context = mpipe_context;

  // Get the instance.
  int instance = gxio_mpipe_link_instance(interfaces[0]);
  if (instance < 0)
    tmc_task_die("Link '%s' does not exist.", interfaces[0]);

  // Start the driver.
  result = gxio_mpipe_init(context, instance);
  VERIFY(result, "gxio_mpipe_init()");

  channels = OVH_MALLOC(sizeof(*channels) * nb_interfaces);
  for (int i = 0; i < nb_interfaces; i++)
  {
    gxio_mpipe_link_t link;
    result = gxio_mpipe_link_open(&link, context, interfaces[i], 0);
    if (result < 0)
      tmc_task_die("gxio_mpipe_link_open() : %s", interfaces[i]);
    channels[i] = gxio_mpipe_link_channel(&link);
  }

  // Allocate some NotifRings.
  result = gxio_mpipe_alloc_notif_rings(context, work_size, 0, 0);
  VERIFY(result, "gxio_mpipe_alloc_notif_rings()");
  unsigned int ring = result;

  // Init the NotifRings.
  size_t notif_ring_entries = 2048;
  size_t notif_ring_size = notif_ring_entries * sizeof(gxio_mpipe_idesc_t);
  size_t needed = notif_ring_size + sizeof(gxio_mpipe_iqueue_t);
  for (int i = 0; i < work_size; i++)
  {
    tmc_alloc_t alloc = TMC_ALLOC_INIT;
    tmc_alloc_set_home(&alloc, tmc_cpus_find_nth_cpu(&dataplane_cpus, i));
    // The ring must use physically contiguous memory, but the iqueue
    // can span pages, so we use "notif_ring_size", not "needed".
    tmc_alloc_set_pagesize(&alloc, notif_ring_size);
    void* iqueue_mem = tmc_alloc_map(&alloc, needed);
    if (iqueue_mem == NULL)
      tmc_task_die("Failure in 'tmc_alloc_map()'.");
    gxio_mpipe_iqueue_t* iqueue = iqueue_mem + notif_ring_size;
    result = gxio_mpipe_iqueue_init(iqueue, context, ring + i,
                                    iqueue_mem, notif_ring_size, 0);
    VERIFY(result, "gxio_mpipe_iqueue_init()");
    queues1[i] = iqueue;
  }


  // Allocate a NotifGroup.
  result = gxio_mpipe_alloc_notif_groups(context, 1, 0, 0);
  VERIFY(result, "gxio_mpipe_alloc_notif_groups()");
  int group = result;

  // Allocate some buckets. The default mPipe classifier requires
  // the number of buckets to be a power of two (maximum of 4096).
  result = gxio_mpipe_alloc_buckets(context, num_buckets, 0, 0);
  VERIFY(result, "gxio_mpipe_alloc_buckets()");
  bucket = result;

  // Init group and buckets, preserving packet order among flows.
  gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_STICKY_FLOW_LOCALITY;
  result = gxio_mpipe_init_notif_group_and_buckets(context, group,
                                                   ring, work_size,
                                                   bucket, num_buckets, mode);
  VERIFY(result, "gxio_mpipe_init_notif_group_and_buckets()");

// The platform limits us to 24 equeues, which needs to be divided by the number of links we handle
#define MPIPE_MAX_EQUEUES 24

  // Initialize the equeues
  max_equeues = MPIPE_MAX_EQUEUES / nb_interfaces;
  equeuesW = OVH_MALLOC(max_equeues * sizeof(*equeuesW));
  for (int w = 0; w < max_equeues; w++)
  {
    // ATM, max possible channel is 12
    equeuesW[w] = OVH_MALLOC(13 * sizeof(**equeuesW));
    for (int i = 0; i < nb_interfaces; i++)
    {
      int channel = channels[i];
      result = gxio_mpipe_alloc_edma_rings(context, 1, 0, 0);
      VERIFY(result, "gxio_mpipe_alloc_edma_rings");
      uint ering = result;
      size_t edescs_size = equeue_entries * sizeof(gxio_mpipe_edesc_t);
      tmc_alloc_t edescs_alloc = TMC_ALLOC_INIT;
      tmc_alloc_set_pagesize(&edescs_alloc, edescs_size);
      void* edescs = tmc_alloc_map(&edescs_alloc, edescs_size);
      if (edescs == NULL)
        tmc_task_die("Failed to allocate equeue memory.");
      NETIO_EQUEUE_T *equeue = OVH_CALLOC(1, sizeof(NETIO_EQUEUE_T));
      result = gxio_mpipe_equeue_init(equeue, context, ering, channel,
                                      edescs, edescs_size, 0);
      VERIFY(result, "gxio_gxio_equeue_init()");

      equeuesW[w][channel] = equeue;
    }
  }


  // Use enough small/large buffers to avoid ever getting "idesc->be".
  unsigned int num_bufs = (equeue_entries * MPIPE_MAX_EQUEUES) + work_size * notif_ring_entries + OFP_PCAP_DUMP_REQUEST_RING_SIZE * work_size;

  // Allocate small/large buffer stacks.
  result = gxio_mpipe_alloc_buffer_stacks(context, 2, 0, 0);
  VERIFY(result, "gxio_mpipe_alloc_buffer_stacks()");
  int stack_idx = result;

  stack_idx_small_buf = stack_idx;
  stack_idx_large_buf = stack_idx + 1;
  // Initialize small/large stacks.
  create_stack(context, stack_idx_small_buf, GXIO_MPIPE_BUFFER_SIZE_128, num_bufs);
  create_stack(context, stack_idx_large_buf, GXIO_MPIPE_BUFFER_SIZE_1664, num_bufs);
  PRINT_INFO("ofp_mpipe_init done.\n");
}

void ofp_mpipe_start()
{
  PRINT_INFO("ofp_mpipe_start()\n");
  gxio_mpipe_context_t* context = mpipe_context;

  // Register for packets.
  gxio_mpipe_rules_t rules;
  gxio_mpipe_rules_init(&rules, context);
  gxio_mpipe_rules_begin(&rules, bucket, num_buckets, NULL);
  int result = gxio_mpipe_rules_commit(&rules);
  VERIFY(result, "gxio_mpipe_rules_commit()");

  PRINT_INFO("ofp_mpipe_start done.\n");
}

// Allocate memory for a buffer stack and its buffers, initialize the
// stack, and push buffers onto it.
//
static void create_stack(gxio_mpipe_context_t* context, int stack_idx, gxio_mpipe_buffer_size_enum_t buf_size, int num_buffers)
{
  int result;

  // Extract the actual buffer size from the enum.
  size_t size = gxio_mpipe_buffer_size_enum_to_buffer_size(buf_size);

  // Compute the total bytes needed for the stack itself.
  size_t stack_bytes = gxio_mpipe_calc_buffer_stack_bytes(num_buffers);

  // Round up so that the buffers will be properly aligned.
  stack_bytes += -(long)stack_bytes & (128 - 1);

  // Compute the total bytes needed for the stack plus the buffers.
  size_t needed = stack_bytes + num_buffers * size;

  // Allocate up to 16 pages of the smallest suitable pagesize.
  tmc_alloc_t alloc = TMC_ALLOC_INIT;
  tmc_alloc_set_pagesize(&alloc, needed / 16);
  size_t pagesize = tmc_alloc_get_pagesize(&alloc);
  int pages = (needed + pagesize - 1) / pagesize;
  void* mem = tmc_alloc_map(&alloc, pages * pagesize);
  if (mem == NULL)
    tmc_task_die("Could not allocate buffer pages.");

  // Initialize the buffer stack.
  result = gxio_mpipe_init_buffer_stack(context, stack_idx, buf_size,
                                        mem, stack_bytes, 0);
  VERIFY(result, "gxio_mpipe_init_buffer_stack()");

  // Register the buffer pages.
  for (int i = 0; i < pages; i++)
  {
    result = gxio_mpipe_register_page(context, stack_idx,
                                      mem + i * pagesize, pagesize, 0);
    VERIFY(result, "gxio_mpipe_register_page()");
  }

  // Push the actual buffers.
  mem += stack_bytes;
  for (int i = 0; i < num_buffers; i++)
  {
    gxio_mpipe_push_buffer(context, stack_idx, mem);
    mem += size;
  }
}

#else //TILPRO

//========================================
// NetIO configuration.
static int max_receive_packets = 1500;
static int max_small_packets = NETIO_MAX_SEND_BUFFERS, max_large_packets = NETIO_MAX_SEND_BUFFERS;

// Configure a queue.
// For a shared queue, we are careful to register workers serially.
//
void
ofp_netio_queue_config(int work_rank, netio_queue_t *queue, int qid,char *interface, int recv)
{
  netio_input_config_t config = {
    .flags = recv ? NETIO_RECV | NETIO_XMIT | NETIO_TAG_NONE : NETIO_NO_RECV | NETIO_XMIT,
    .total_buffer_size = 4 * 16 * 1024 * 1024,
    .buffer_node_weights = { 0, 1, 1, 0 },
    .num_receive_packets = max_receive_packets,
    .interface = interface,
    .num_send_buffers_small_total = max_small_packets,
    .num_send_buffers_large_total = max_large_packets,
    .num_send_buffers_small_prealloc = max_small_packets,
    .num_send_buffers_large_prealloc = max_large_packets,
#if NO_FLOW_HASHING
    .queue_id = recv ? 0 : NETIO_MAX_QUEUE_ID
#else
    .queue_id = recv ? qid : NETIO_MAX_QUEUE_ID
#endif
  };

  // Loop on netio_input_register() in case the link is down.
  while (1)
  {
      printf(" POURT worker %d/%d\n", work_rank, work_size);
      netio_error_t err = netio_input_register(&config, queue);
      if (err == NETIO_NO_ERROR)
          break;
      else if (err == NETIO_LINK_DOWN)
      {
          fprintf(stderr, "Link %s is down, retrying.\n", interface);
          sleep(2);
          continue;
    }
    else
    {
      tmc_task_die("netio input_register %d failed on %s, status %d(%s)\n",
               work_rank, interface,err, netio_strerror(err));
    }
  }
  PRINT_D2("worker %d/%d\n", work_rank, work_size);
}

// Define a flow hash across a set of buckets.
// Map the buckets to our worker queues.
// There should be at least as many buckets as workers.
//
void ofp_netio_flow_config(netio_queue_t *queue, netio_group_t* flowtbl, int base, unsigned count)
{
#define N_BUCKETS 1024
#if NO_FLOW_HASHING
  // Map each bucket to a single queue.  This puts us in a big round-robin mode
  netio_bucket_t bucket = 0;
  netio_error_t err = netio_input_bucket_configure(queue, base, &bucket, 1);
#else
  netio_bucket_t map[N_BUCKETS];
  for (int b = 0; b < N_BUCKETS; ++b)
    map[b] = b % work_size;
  netio_error_t err = netio_input_bucket_configure(queue, base, map, N_BUCKETS);
#endif
  if (err != NETIO_NO_ERROR)
    tmc_task_die("netio_input_bucket_configure(%d) returned: %d(%s)\n",
               count, err, netio_strerror(err));

#if NO_FLOW_HASHING
  flowtbl->bits.__balance_on_l3 = 1;    // Hash on IP addresses (just because we use the generated flow hash in our code, not for queue-assigning)
  flowtbl->bits.__bucket_base = 0;
  flowtbl->bits.__bucket_mask = 0;
#else
  flowtbl->word = 0;
  flowtbl->bits.__balance_on_l4 = 0;    // Hash on ports?
  flowtbl->bits.__balance_on_l3 = 1;    // Hash on IP addresses
  flowtbl->bits.__balance_on_l2 = 0;    // Hash on Ethernet Mac address
  flowtbl->bits.__bucket_base = base;   // Hash table
  flowtbl->bits.__bucket_mask = N_BUCKETS - 1;
#endif
}

// Configure mapping group > buckets
//
void ofp_netio_group_config(netio_queue_t *queue, netio_group_t* flowtbl, int base, int count)
{
  for (int v = base; v < count; ++v)
  {
    netio_error_t err = netio_input_group_configure(queue, v, flowtbl, 1);
    if (err != NETIO_NO_ERROR)
      tmc_task_die("netio_input_group_configure(%d) failed, status: %d(%s)\n",
                v, err, netio_strerror(err));
  }
}
#endif // /TILEPRO
