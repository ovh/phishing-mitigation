#ifndef __OFP_CONFIG_IP_H__
#define __OFP_CONFIG_IP_H__

#include "ofp_phish_target_host_ht.h"
#include "ofp_phish_target_ip_ht.h"
#include "ofp_phish_desc_ht.h"

typedef enum { DeltaOppError = -1, DeltaOppUnknown = 0, DeltaOppAdd = 1, DeltaOppRemove = 2 } delta_opp_t;

extern ofp_phish_target_host_ht_t* config_host_hash;
extern ofp_phish_desc_hash_table_t* config_desc_hash;
extern ofp_phish_target_ip_ht_t* config_ip_hash;

void config_ip_init();
void config_ip_close();

void config_ip_alloc_shared(tmc_alloc_t *alloc);


////////////////////////////////////////////////////////////
////
////      Add/Remove DESC
////
////////////////////////////////////////////////////////////
int config_ip_desc_parse_delta_lines(ofp_phish_desc_hash_table_locked_t locked, char* lines);
int config_ip_desc_parse_delta_line(ofp_phish_desc_hash_table_locked_t locked, const char* line, int lineNumber);
int config_ip_desc_parse_delta_line2(ofp_phish_desc_hash_table_locked_t locked, const char* line, int lineLen, int lineNumber);
int config_ip_desc_add_line(ofp_phish_desc_hash_table_locked_t locked, const char* line, int lineNumber);
int config_ip_desc_add_lines(ofp_phish_desc_hash_table_locked_t locked, const char** lines, uint32_t lineCount);
int config_ip_desc_add_file(ofp_phish_desc_hash_table_locked_t locked, const char* fileName);
int config_ip_desc_save_file(ofp_phish_desc_hash_table_locked_t locked, const char* fileName);


////////////////////////////////////////////////////////////
////
////      Parse DESC to TARTGET
////
////////////////////////////////////////////////////////////
//=======================================================================================================
// Expect value as  :
// 10.254.0.8 http://www.example.com/index.html
// param should be 'x' as eXclude phishing target
//=======================================================================================================

ofp_phish_target_host_t* config_ip_target_parse(ofp_phish_target_host_ht_t *hash, ofp_phish_target_ip_ht_t *byIpHash, const char* arg, target_type targetType, int lineNumber);
ofp_phish_target_host_t* config_ip_target_parse_desc(ofp_phish_target_host_ht_t* hash, ofp_phish_target_ip_ht_t *byIpHash, const char* desc, int lineNumber);
int config_ip_target_parse_desc_ht(ofp_phish_target_host_ht_t *hash, ofp_phish_target_ip_ht_t *byIpHash, ofp_phish_desc_hash_table_locked_t locked);


#endif //__OFP_CONFIG_IP_H__
