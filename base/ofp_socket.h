#ifndef __OFP_SOCKET_H__
#define __OFP_SOCKET_H__

#if SOCKET

typedef int (*socket_message_cb_t)(int sock, char *data);
typedef int (*socket_error_cb_t)(int sock);

void socket_start(socket_message_cb_t meesage_cb, socket_error_cb_t error_cb);
void socket_stop();


#endif //SOCKET

#endif //__OFP_SOCKET_H__
