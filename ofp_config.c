#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ofp.h"
#include "ofp_phish.h"
#include "ofp_config.h"
#include "ofp_config_ip.h"
#include "ofp_init.h"
#include "ofp_logger.h"
#include "ofp_main.h"


#if TMC
#include <tmc/task.h>
#include <tmc/alloc.h>
#include <tmc/cpus.h>


int config_bridge_mode = 1;
int config_daemonize = 0;


#if TILEGX
static void parse_links(int lineNumber, const char* argument)
{
  char* argdup = strdup(argument);
  char* arg = argdup;

  PRINT_INFO("parse_links()\n");

  char *links[4];
  const int max_link_count = sizeof(links) / sizeof(char*);
  memset(links, 0, sizeof(links));
  links[0] = strtok(arg, ",");
  int i = 1;
  char *tmp;
  while (i < max_link_count && (tmp = strtok(NULL, ",")) != NULL)
  {
    links[i] = tmp;
    if(i>=max_link_count)
    {
      PRINT_ERR("too many links in config file(%d) : %s",lineNumber, argument);
    }
    i++;
  }
  nb_interfaces = i;
  PRINT_INFO("nb_interfaces = %d\n", nb_interfaces);
  if (interfaces != NULL)
  {
    OVH_FREE(interfaces);
  }
  interfaces = OVH_CALLOC(nb_interfaces, sizeof(char*));
  for (i = 0; i < nb_interfaces; i++)
  {
    interfaces[i] = links[i];
    PRINT_INFO("interfaces[%d] = %s\n", i, links[i]);
  }
}
#endif



//=======================================================================================================
// ip.conf Configuration file
//=======================================================================================================
char* config_ip_file_name = NULL;

int parse_ip_configuration_file(int reload)
{
  if (config_ip_file_name == NULL)
  {
    PRINT_D2("No config file provided\n");

    if (reload != 0 && unlink(OFP_RELOAD_LOCK_FILE) != 0)
      PRINT_ERR("Fail to delete reload lock file: %s\n", strerror(errno));
    return 0;
  }

  ofp_phish_desc_hash_table_locked_t config_desc_locked = ofp_phish_desc_ht_lock(config_desc_hash);
  OVH_ASSERT(OVH_HASH_COUNT(config_host_hash) == 0); //all clean ?
  ofp_phish_desc_ht_free_elements(config_desc_locked);
  OVH_ASSERT(OVH_HASH_COUNT(config_desc_locked.hash) == 0); //all clean ?

  int result = config_ip_desc_add_file(config_desc_locked, config_ip_file_name);
  result &= config_ip_target_parse_desc_ht(config_host_hash, config_ip_hash, config_desc_locked);

  if(result == 0)
  {
    ofp_phish_desc_ht_unlock(config_desc_locked);
    PRINT_ERR("Fail to update phishing list\n");
    if (reload != 0 && unlink(OFP_RELOAD_LOCK_FILE) != 0)
      PRINT_ERR("Fail to delete reload lock file: %s\n", strerror(errno));
    return result;
  }

  PRINT_D2("syncing workers phishing targets\n");

  ofp_phish_target_host_ht_locked_t config_host_locked = ofp_phish_target_by_host_lock(config_host_hash);
  ofp_phish_target_ip_ht_locked_t config_ip_locked = ofp_phish_target_by_ip_lock(config_ip_hash);

  phish_fill_from(config_host_locked, config_ip_locked);
  config_desc_locked.hash->dirty = 0;

  ofp_phish_target_by_ip_free_elements(config_ip_locked);
  ofp_phish_target_by_ip_unlock(config_ip_locked);

  ofp_phish_target_by_host_free_elements(config_host_locked);
  ofp_phish_target_by_host_unlock(config_host_locked);

  ofp_phish_desc_ht_unlock(config_desc_locked);

  if (reload != 0 && unlink(OFP_RELOAD_LOCK_FILE) != 0)
    PRINT_ERR("Fail to delete reload lock file: %s\n", strerror(errno));
  return 1;
}

//=======================================================================================================
// Configuration file
//=======================================================================================================
static char* confFilename = NULL;

// reload : set to 1 if we are reloading the conf while running
// When we are reloading, only some options can be changed. E.g. 'workers' can not, it needs a restart
void parse_main_configuration_file(int reload)
{
  if (confFilename == NULL)
  {
    PRINT_D2("No config file provided\n");
    return;
  }
  FILE *confFile = fopen(confFilename, "r");
  if (confFile == NULL)
    tmc_task_die("Error opening config file %s\n", confFilename);


  PRINT_INFO("Loading config file %s\n", confFilename);

  char * line = NULL;
  size_t len = 0;
  ssize_t read;
  int lineCount = 0;

  while ((read = getline(&line, &len, confFile)) != -1) {
    lineCount++;
    int lineNumber = lineCount;

    // Ignore empty lines and lines starting with '#'
    if (strcmp(line, "\n") == 0 || line[0] == '#')
      continue;
    // Duplicate line since strtok modifies its arg
    char *dup_line = strdup(line);
    char *param = strtok(dup_line, "=");
    char *value = strtok(NULL, "\n");
    if (value == NULL)
      tmc_task_die("Error parsing config file(%d), param '%s' has no value\n", lineNumber, param);
    if (!reload && !strcmp(param, "workers"))
      work_size = atoi(value);
#if TILEGX
    else if (!reload && !strcmp(param, "links"))
      parse_links(lineNumber, value);
#endif
    else if (!strcmp(param, "monitoring_ip_port"))
    {
      ip_port_tuple ip_port = {0};
      if(!parse_ip(value, 0, &ip_port))
      {
        tmc_task_die("Error parsing config file(%d), param '%s' parsing ip '%s'\n", lineNumber, param, value);
      }
      ofp_logger_addr.sin_port = htons(ip_port.port);
      ofp_logger_addr.sin_addr.s_addr = htonl(ip_port.ip);
    }
    else if (!strcmp(param, "bridge_mode") && !reload)
    {
      PRINT_D5("read bridge_mode = '%s'\n", value);
      config_bridge_mode = atoi(value);
    }

    OVH_FREE(dup_line);
  }

  if (line != NULL)
    OVH_FREE(line);

  fclose(confFile);


  PRINT_INFO("config_bridge_mode = %d\n", config_bridge_mode);

}

// reload : set to 1 if we are reloading the conf while running
// When we are reloading, only some options can be changed. E.g. 'workers' can not, it needs a restart
void parse_configuration_file(int reload)
{
  parse_main_configuration_file(reload);
  //TODO find a better way to call that
  if(reload)
  {
    parse_ip_configuration_file(reload);
  }
}

static char *shift_option(char ***arglist, const char *option)
{
  char **args = *arglist;
  char *first = args[0], **rest = &args[1];

  int optlen = strlen(option);
  char *val = first + optlen;

  if (option[optlen-1] != '=')
  {

    // Simple option without operand.
    //
    if (strcmp(first, option))
      return NULL;
  }
  else
  {
    // Option with operand.
    //
    if (strncmp(first, option, optlen - 1))
      return NULL;

    // Look for operand attached or in next argument.
    //
    if (first[optlen - 1] == '\0')
      val = *rest++;
    else if (first[optlen - 1] != '=')
      return NULL;
  }

  // Update argument list.
  //
  *arglist = rest;
  return val;
}

void parse_configuration_args(int argc, char** argv)
{

  // Scan options.
  //
  char **args = &argv[1];
  while (*args)
  {
    char *opt = NULL;

    //TODO handle conflicts between args & conf file ?
    if ((opt = shift_option(&args, "--conf=")))
      confFilename = opt;
    else if ((opt = shift_option(&args, "--ip-conf=")))
      config_ip_file_name = opt;
    else if ((opt = shift_option(&args, "--discard")))
      packet_drop = 1;
#if OFP_LOOP_STATISTICS
    else if ((opt = shift_option(&args, "--limit-packets=")))
      limit_packets = strtoul(opt,NULL,0);
#endif
    else if ((opt = shift_option(&args, "--workers=")))
      work_size = atoi(opt);
#if TILEGX
    else if ((opt = shift_option(&args, "--links=")))
      parse_links(0, opt);
#else
#if TWOINTERFACE
    else if ((opt = shift_option(&args, "--interface1=")))
      interface1 = opt;
    else if ((opt = shift_option(&args, "--interface2=")))
      interface2 = opt;
#else
    else if ((opt = shift_option(&args, "--interface=")))
      interface1 = opt;
#endif
#endif
#if MODE_VLAN
    else if ((opt = shift_option(&args, "--vlan1=")))
      packet_vlan_swap1 = strtoul(opt,NULL,0);
    else if ((opt = shift_option(&args, "--vlan2=")))
      packet_vlan_swap2 = strtoul(opt,NULL,0);
#endif
    else if ((opt = shift_option(&args, "--daemon")))
      config_daemonize = 1;

    else
      tmc_task_die("Unknown option '%s'.\n", args[0]);
  }
}

#endif