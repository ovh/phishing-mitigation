#include <stdio.h>
#include "ovh_common.h"
#include "ofp_socket.h"
#include "ofp_defines.h"
#include "ofp_init.h"
#include "ofp_workers.h"
#include "ofp_socket_message_cb.h"
#include "ofp_config_ip.h"

//const char* ip_conf_filename = "../../conf/ip.conf";
//const char* ip_conf_filename = "./ip.conf";
const char* ip_conf_filename = "../python/ip.tmp.conf";

static int ofp_socket_test_message_cb(int socket, char* data)
{
  printf("test received : '%s'\n", data);
  int res = ofp_socket_message_cb(socket, data);
  ofp_phish_desc_hash_table_locked_t config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);
  config_ip_desc_save_file(config_desc_locked, ip_conf_filename);
  return res;
}

static int ofp_socket_test_error_cb(int socket)
{
  printf("test socket error \n");
  prgm_exit_requested = 1;
  return 0;
}

static void ofp_socket_loop()
{
  printf("using file %s\n", ip_conf_filename);
  ofp_phish_desc_hash_table_locked_t descsLocked = ofp_phish_desc_ht_lock(config_desc_hash);
  int result = config_ip_desc_add_file(descsLocked, ip_conf_filename);
  OVH_ASSERT(1 == result);
  ofp_phish_desc_ht_unlock(descsLocked);

  socket_start(ofp_socket_test_message_cb, ofp_socket_test_error_cb);

  printf("Waiting for incoming connections...\n");
  while(!prgm_exit_requested)
  {
  }

  descsLocked = ofp_phish_desc_ht_lock(config_desc_hash);
  ofp_phish_desc_ht_free_elements(descsLocked);
  ofp_phish_desc_ht_unlock(descsLocked);
  socket_stop();

}

SUPPRESS_UNUSED_WARN(ofp_socket_test_message_cb);
SUPPRESS_UNUSED_WARN(ofp_socket_test_error_cb);



int main(int argc, char* argv[])
{
  ofp_log_startup();

  int workerCount = 29;
  ofp_init(workerCount, 0);
  ofp_init_alloc_shared(NULL);

  ofp_socket_loop();

  ofp_free_shared();
  ofp_close();
  return 0;
}

