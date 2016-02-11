#include <stdio.h>
#include "ovh_common.h"
#include "ofp_http.h"
#include "ofp_init.h"
#include "ofp_http_perf.h"

void ofp_http_match_start_with_perf(ofp_http_request_description_t* desc)
{
  ofp_uri_list_t* uris = ofp_uri_list_new();
  int result;
  SUPPRESS_UNUSED_VAR_WARN(result);

  ofp_uri_list_entry_add_uri(uris, "/plop/index.html");
  OVH_UPDATE_CUR_TIME();
  uint64_t loop_count = 1000000;
  uint64_t startMs = OVH_CUR_TIME_MS;
  for (int i = 0; i < loop_count; ++i)
  {
    ofp_uri_list_entry_t* entry = NULL;
    result = http_match(desc, "example.com", uris, &entry);
    //OVH_ASSERT(result == 1);
  }
  OVH_UPDATE_CUR_TIME();
  uint64_t endMs = OVH_CUR_TIME_MS;
  int deltaMs = endMs - startMs;
  printf("ofp_http_match_start_with_perf : %lu iterations took %d ms\n",loop_count, deltaMs);
}

void ofp_http_match_regex_perf(ofp_http_request_description_t* desc)
{
  #if REGEX
  ofp_uri_list_t* uris = ofp_uri_list_new();
  int result;
  SUPPRESS_UNUSED_VAR_WARN(result);

  //ofp_uri_list_entry_add_regex(uris, ovh_regex_new("/plop.*\\.html"));
  //ofp_uri_list_entry_add_regex(uris, ovh_regex_new("/plop/[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}/.*/index\\.html"));
  //ofp_uri_list_entry_add_regex(uris, ovh_regex_new("/plop/(x+x+)+y/index\\.html"));

  ofp_uri_list_entry_add_regex(uris, ovh_regex_new("/i14/[a-zA-Z0-9]{29}/home/"));
  //ofp_uri_list_entry_add_regex(uris, ovh_regex_new("/i14/.*/home/.*/espa"));

  OVH_UPDATE_CUR_TIME();
  uint64_t loop_count = 1000000;
  uint64_t startMs = OVH_CUR_TIME_MS;
  for (int i = 0; i < loop_count; ++i)
  {
    ofp_uri_list_entry_t* entry = NULL;
    result = http_match(desc, "example.com", uris, &entry);
    OVH_ASSERT(result == 1);
  }
  OVH_UPDATE_CUR_TIME();
  uint64_t endMs = OVH_CUR_TIME_MS;
  int deltaMs = endMs - startMs;
  printf("ofp_http_match_regex_perf : %lu iterations took %d ms\n",loop_count, deltaMs);
  #endif
}

int ofp_http_perf(int argc, char* argv[])
{
  ofp_http_request_description_t desc;
  inplace_string_set(&desc.method, "GET");
  inplace_string_set(&desc.host, "example.com");

  //inplace_string_set(&desc.URI, "/plop/index.html?foo=bar");
  //inplace_string_set(&desc.URI, "/plop/A6667406-F0F3-4742-BF5C-98EF0C34439F/foobar/index.html?foo=bar");
  //inplace_string_set(&desc.URI, "/plop/xxxxxxxxxxy/index.html?foo=bar");

  inplace_string_set(&desc.uri, "/i14/6756556WxCXwEeRRfdWxsZere4475/home/Language-xxFr/ZE4RTYU345678765434567654E3ZER5676543ZERT6543ERT6765EZSDfgfdsxcvgvcxSDFGFDE3456787654Esdcvbvcdert765434ERFDCDER56T78/FHFDNnbbvCCddGFDDrerERerSdSDSDxcxcx434356676876/34567876543ZSDFGVVCxsdfgbvcXSZER56765435ESRD67T6S57EDRFT75R6E5SDRFT7R65EDS7DXCRF7T6RD5ESXD7CFTRF6D5E7CRF76RD5E7CRFT786R5ED7CRFED57XCFR6ED75XCF8R65EDX7CFTR65ED7XTCF8CRXEDTCFRCXD7SRDTC8FRXE5D7/SE5DRF7TR564ESRDF7TRD6SERDTYG8DR4TRERT8Y7R6DTREX6SRCY8GRDX6CTRX6CVY8RDX6ECTYTCRX6CVY8TC7RX6VY8TCRX6EC7CRX6ERCFVY8TCRX6CV/ESRDRD6SE5R76R5ESDRT7RD65SEDRCTR6SXERCT77R6DXSERDF/5F6G765DF6G76F5D7F68657DF6G6F5D7F6G7F6G6F5D7FDYG765D7G6FD57FYGYF8GFD75FGFD57F8GYFD77FGYGF5D47F68GFDSfgftrderfgfrdesDRFRFDEFCRDesdfgtrDERF7T86/espa/");

  ofp_http_match_start_with_perf(&desc);
  ofp_http_match_regex_perf(&desc);

  return 0;
}

SUPPRESS_UNUSED_WARN(ofp_http_match_start_with_perf);
SUPPRESS_UNUSED_WARN(ofp_http_match_regex_perf);
