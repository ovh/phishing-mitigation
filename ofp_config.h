#ifndef __OFP_CONFIG_H__
#define __OFP_CONFIG_H__

//=======================================================================================================
// Config options
//=======================================================================================================
extern int config_bridge_mode; // Bridge mode : true | false
extern int config_daemonize;
extern char* config_ip_file_name;

//=======================================================================================================

#define OFP_RELOAD_LOCK_FILE "/var/lock/tilera-phishing-ip-conf.lock"

void parse_configuration_file(int reload);
void parse_configuration_args(int argc, char** argv);
int parse_ip_configuration_file(int reload);



#endif //__OFP_CONFIG_H__
