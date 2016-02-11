/*
 Copyright (C) 2016, OVH SAS

 This file is part of phishing-mitigation.

 phishing-mitigation is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ovh_common.h"
#include "ofp_config_ip.h"
#include "ofp_phish.h"

ofp_phish_target_host_ht_t* config_host_hash;
ofp_phish_desc_hash_table_t* config_desc_hash;
ofp_phish_target_ip_ht_t* config_ip_hash;


void config_ip_init()
{
  config_host_hash = OVH_CALLOC(1, sizeof(ofp_phish_target_host_ht_t));
  OVH_HASH_INIT(config_host_hash, PHISH_TARGET_BY_HOST_BUCKET_SIZE, ofp_phish_target_host_t);
  config_desc_hash = OVH_CALLOC(1, sizeof(ofp_phish_desc_hash_table_t));
  OVH_HASH_INIT(config_desc_hash, PHISH_DESC_BUCKET_SIZE, ofp_phish_desc_t);
  config_ip_hash = OVH_CALLOC(1, sizeof(ofp_phish_target_ip_ht_t));
  OVH_HASH_INIT(config_ip_hash, PHISH_TARGET_BY_IP_BUCKET_SIZE, ofp_phish_target_ip_t);
}

void config_ip_close()
{
  OVH_HASH_DISCARD(config_host_hash);
  OVH_FREE(config_host_hash);

  OVH_HASH_DISCARD(config_desc_hash);
  OVH_FREE(config_desc_hash);

  OVH_HASH_DISCARD(config_ip_hash);
  OVH_FREE(config_ip_hash);
}

void config_ip_alloc_shared(tmc_alloc_t *alloc)
{
}



////////////////////////////////////////////////////////////
////
////      Add/Remove DESC
////
////////////////////////////////////////////////////////////
int config_ip_desc_add_line(ofp_phish_desc_hash_table_locked_t locked, const char* line, int lineNumber)
{
  //PRINT_D5("config_ip_desc_add_line(%s)\n", line);

  locked.hash->dirty = 1;
  return ofp_phish_desc_ht_insert(locked, line);
}

int config_ip_desc_parse_delta_lines(ofp_phish_desc_hash_table_locked_t locked, char* lines)
{
  char *one_line = strtok(lines, "\n");
  while(one_line != NULL)
  {
    int result = config_ip_desc_parse_delta_line(locked, one_line, 0);
    if(result == 0) return result;

    one_line = strtok(NULL, "\n");
    //PRINT_D5("parsing '%s'\n", one_line);
  }
  return 1;
}

int config_ip_desc_parse_delta_line(ofp_phish_desc_hash_table_locked_t locked, const char* line, int lineNumber)
{
  return config_ip_desc_parse_delta_line2(locked, line, strlen(line), lineNumber);
}

int config_ip_desc_parse_delta_line2(ofp_phish_desc_hash_table_locked_t locked, const char* line, int lineLen, int lineNumber)
{
  OVH_ASSERT(line != NULL);
  delta_opp_t delta_opp = DeltaOppUnknown;
  if(lineLen<2) return 0; //need at least 2 chars

  //Get Operation
  if(line[0]=='+')
  {
    delta_opp = DeltaOppAdd;
  }
  else if(line[0]=='-')
  {
    delta_opp = DeltaOppRemove;
  }
  else
  {
    PRINT_ERR("unknown delta_opp in line %s\n", line);
    return 0;
  }
  const char* data = line+1; //skip OP char
  lineLen--;
  OVH_ASSERT(lineLen>0);

  const char* start_line = data;

  const char* end_line = memchr(start_line, '\n', lineLen);
  if(end_line != NULL)
  {
    lineLen = OVH_MIN(lineLen, end_line - start_line);
  }

  const char* end_line2 = memchr(start_line, '\r', lineLen);
  if(end_line2 != NULL)
  {
    lineLen = OVH_MIN(lineLen, end_line2 - start_line);
  }

  int changeCount = 0;
  int op_result = 0;

  if(delta_opp == DeltaOppAdd)
  {
    PRINT_D5("desc upsert '%.*s'\n", lineLen, start_line);
    op_result = ofp_phish_desc_ht_upsert2(locked, start_line, lineLen);
    if(op_result > 0) changeCount++;
  }
  else if(delta_opp == DeltaOppRemove)
  {
    PRINT_D5("desc remove '%.*s'\n", lineLen, start_line);
    op_result = ofp_phish_desc_ht_free2(locked, start_line, lineLen);
    if(op_result > 0) changeCount++;
  }
  else
  {
    PRINT_ERR("unknown delta_opp %d\n", delta_opp);
    return 0;
  }


  if(changeCount>0)
  {
    locked.hash->dirty = 1;
    /*
#if DEBUG >= 5
    PRINT_D5("desc count '%d'\n", HASH_COUNT(locked.hash->head));
    ofp_phish_desc_t *desc=NULL, *tmp=NULL;
    OVH_HASH_ITER(locked.hash, desc, tmp)
    {
      PRINT_D5("'%s'\n", desc->data);
    }
#endif
*/
  }
  else
  {
    PRINT_D5("delta_line '%.*s' have not changed anything to desc hashtable content\n", lineLen, start_line);
  }
  return 1;
}

int config_ip_desc_add_lines(ofp_phish_desc_hash_table_locked_t locked, const char** lines, uint32_t lineCount)
{
  OVH_ASSERT(lines != NULL);
  OVH_ASSERT(lineCount >= 0);
  OVH_ASSERT(locked.hash != NULL);

  for (int i = 0; i < lineCount; ++i)
  {
    const char* line = lines[i];

    config_ip_desc_add_line(locked, line, i);
  }

  return 1;
}

int config_ip_desc_add_file(ofp_phish_desc_hash_table_locked_t locked, const char* fileName)
{
  OVH_ASSERT(fileName != NULL);
  OVH_ASSERT(locked.hash != NULL);

  FILE *confFile = fopen(fileName, "r");
  if (confFile == NULL)
    FAIL("Error opening config file %s\n", fileName);

  char * line = NULL;
  size_t len = 0;
  ssize_t read;
  int lineCount = 0;


  while ((read = getline(&line, &len, confFile)) != -1)
  {
    lineCount++;
    int lineNumber = lineCount;

    // Ignore empty lines and lines starting with '#'
    if (strcmp(line, "\n") == 0 || line[0] == '#')
      continue;

    char *dup_line = strdup(line);
    char *start_line = strtok(dup_line, "\r\n"); //make strtok to remove \r\n
    if(start_line != dup_line)
    {
      PRINT_ERR("fail to parse line %s\n", line);
      continue;
    }

    config_ip_desc_add_line(locked, start_line, lineNumber);
    OVH_FREE(dup_line);
  }
  OVH_FREE(line);
  fclose(confFile);

  return 1;
}

int config_ip_desc_save_file(ofp_phish_desc_hash_table_locked_t locked, const char* fileName)
{
  OVH_ASSERT(fileName != NULL);
  OVH_ASSERT(locked.hash != NULL);
  PRINT_D5("config_ip_desc_save_file to '%s'\n", fileName);

  FILE *confFile = fopen(fileName, "w");
  if (confFile == NULL)
  {
    PRINT_ERR("Error opening config file %s\n", fileName);
    return 0;
  }

  ofp_phish_desc_t *desc=NULL, *tmp=NULL;
  OVH_HASH_ITER(locked.hash, desc, tmp)
  {
    fprintf(confFile, "%s\n", desc->data);
  }

  fflush(confFile);
  fclose(confFile);

  return 1;
}

////////////////////////////////////////////////////////////
////
////      Parse DESC to TARTGET
////
////////////////////////////////////////////////////////////
ofp_phish_target_host_t* config_ip_target_parse(ofp_phish_target_host_ht_t *hash, ofp_phish_target_ip_ht_t *byIpHash, const char* arg, target_type targetType, int lineNumber)
{
  PRINT_D5("parsing '%s'\n", arg);
  OVH_ASSERT(targetType > 0); //valid target type ?


  char* const spaceToken = strchr(arg, ' ');
  if (spaceToken == NULL)
  {
    PRINT_ERR("Error parsing ip from config file(%d) has malformed value(%s) \n", lineNumber, arg);
    return NULL;
  }
  char* value = spaceToken + 1;

  static const char HTTP_PREFIX[] = "http://";
  static const int HTTP_PREFIX_LEN = sizeof(HTTP_PREFIX) - 1;

  char *data = NULL;
  char *dup_value = strdup(value); //TODO leak if error
  if(strncmp(value, HTTP_PREFIX, HTTP_PREFIX_LEN) == 0)
  {
    data = dup_value + HTTP_PREFIX_LEN;
  }
  else
  {//we assume "http://"" has been omited and string start imediatly with "hostname:port/path"
    data = dup_value;
  }



  if(strstr(data, "www.") == data) //start with "www."
  {
    data += strlen("www."); //skip it
  }

  char *hostName = NULL;
  char* token = strchr(data, '/');
  if (token != NULL)
  {
    if((token - data) <= 0)
    {
      PRINT_ERR("Error parsing hostName from config file(%d), has malformed value(%s) \n", lineNumber, arg);
      return NULL;
    }
    hostName = strndup(data, token - data);//TODO leak
  }
  else
  {
    hostName = strdup(data);
  }

  PRINT_D5("read hostName = '%s'\n", hostName);
  int hostNamePort = 0;
  parse_host_with_port(hostName, &hostNamePort); //parse hostname to extract port, and normalize "host:80" to "host"
  OVH_ASSERT(hostNamePort != 0);
  data = token;

  char *uri = strtok(data, "\n");
  PRINT_D5("read uri = '%s'\n", uri);
  if(uri == NULL)
  {
    uri = "/"; //replace no path with "/" path
  }

  ip_port_tuple destIpPort = {0};
  int ipLen = spaceToken - arg;
  if(ipLen > 0 )
  {
    char* ip = strndup(arg, ipLen);
    parse_ip(ip, 0, &destIpPort);
    OVH_FREE(ip);
  }
  else
  {
    PRINT_ERR("Error parsing ip from config file(%d), has malformed value(%s) \n", lineNumber, arg);
    return NULL;
  }
  //we do not use the port from ip:port but the one from host:port
  destIpPort.port = hostNamePort;

  ofp_phish_target_ip_ht_locked_t byIpLocked = ofp_phish_target_by_ip_lock(byIpHash);
  ofp_phish_target_ip_t* targetIp = ofp_phish_target_by_ip_find(byIpLocked, destIpPort);
  if(targetIp == NULL)
  {
    targetIp = ofp_phish_target_ip_new_init(destIpPort);
    ofp_phish_target_by_ip_insert(byIpLocked, targetIp);
  }
  else
  {
    //already in list , nothing to do
  }
  ofp_phish_target_by_ip_unlock(byIpLocked);


  ofp_phish_target_host_ht_locked_t locked = ofp_phish_target_by_host_lock(hash);
  ofp_phish_target_host_t* desc = ofp_phish_target_by_host_find(locked, hostName);
  if(desc == NULL)
  {
    desc = ofp_phish_target_new_dup(hostName);
    ofp_phish_target_by_host_insert(locked, desc);
  }
  else
  {
    //already in list , nothing to do
  }
  OVH_ASSERT(strcmp(desc->host, hostName) == 0);
  OVH_FREE(hostName);

  if(targetType == TargetURI)
  {
    char* uriDup = strdup(uri);
    ofp_uri_list_entry_add_uri(desc->uriList, uriDup);
  }
#if REGEX
  else if(targetType == TargetPattern)
  {
    ovh_regex_t* regex = ovh_regex_new(uri);
    ofp_uri_list_entry_add_regex(desc->uriList, regex);
  }
#endif
  else
  {
    PRINT_ERR("unknown target type : %d\n", targetType);
    ofp_phish_target_by_host_unlock(locked);
    return NULL;
  }
  PRINT_D5("current uri count for host '%s' = %d\n", desc->host, desc->uriList->count);

  ofp_phish_target_by_host_unlock(locked);
  OVH_FREE(dup_value);
  return desc;
}

ofp_phish_target_host_t* config_ip_target_parse_desc(ofp_phish_target_host_ht_t* hash, ofp_phish_target_ip_ht_t *byIpHash, const char* desc, int lineNumber)
{
  OVH_ASSERT(hash != NULL);
  OVH_ASSERT(desc != NULL);

  char *dup_line = strdup(desc);
  char *param = strtok(dup_line, " ");
  char *value = strtok(NULL, "\n");

  target_type targetType = str_to_target_type(param);
  if(targetType<=0)
  {
    PRINT_ERR("invalid param = '%s' in conf file(%d)\n", param, lineNumber);
    OVH_FREE(dup_line);
    return NULL;
  }

  ofp_phish_target_host_t* result = config_ip_target_parse(hash, byIpHash, value, targetType, lineNumber);
  OVH_FREE(dup_line);
  return result;
}

int config_ip_target_parse_desc_ht(ofp_phish_target_host_ht_t *hash, ofp_phish_target_ip_ht_t *byIpHash, ofp_phish_desc_hash_table_locked_t locked)
{
  OVH_HASH_COMPUTE_STATS(locked.hash);
  ofp_phish_desc_t *desc=NULL, *tmp=NULL;
  OVH_HASH_ITER(locked.hash, desc, tmp)
  {
    config_ip_target_parse_desc(hash, byIpHash, desc->data, 0);
  }
  return 1;
}
