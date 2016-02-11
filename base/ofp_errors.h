#ifndef __OFP_ERRORS_H__
#define __OFP_ERRORS_H__

#define OFP_NO_ERROR 0
#define OFP_ERR_IP_SHORT_PACKET -1
#define OFP_ERR_IP_INVALID_HEADER -2
#define OFP_ERR_IP_INVALID_CHECKSUM -3
#define OFP_ERR_IP_BAD_FRAGMENT -4
#define OFP_ERR_TCP_SHORT_PACKET -5
#define OFP_ERR_TCP_INVALID_HEADER -6
#define OFP_ERR_TCP_INVALID_CHECKSUM -7
#define OFP_ERR_UDP_SHORT_PACKET -8
#define OFP_ERR_UDP_INVALID_CHECKSUM -9
#define OFP_ERR_TCP_SYN_AUTH_NOT_WHITELISTED -10
#define OFP_ERR_DNS_AMP_RATE_LIMITED -11
#define OFP_ERR_UDP_RATE_LIMITED -12
#define OFP_ERR_OUT_OF_MEMORY -13
#define OFP_ERR_NTP_AMP -14

#define OFP_ERRORS_MAX_INDEX 70

const char* ofp_strerror(int errCode);

extern char* str_errors[OFP_ERRORS_MAX_INDEX + 1];

#endif //__OFP_ERRORS_H__