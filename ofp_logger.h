#ifndef __OFP_LOGGER_H__
#define __OFP_LOGGER_H__

extern uint64_t logger_loop_duration_ms;

// Ip & port to which we will send our statistics (in UDP)
extern struct sockaddr_in ofp_logger_addr;

void* logger(void* arg);
void ofp_logger_init(tmc_alloc_t* alloc);


#endif //__OFP_LOGGER_H__
