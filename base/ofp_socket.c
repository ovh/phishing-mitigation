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
#include <stdio.h>
#include <string.h>    //strlen
#include <stdlib.h>    //strlen
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include <signal.h>
#include <pthread.h> //for threading , link with lpthread


#include "ovh_common.h"
#include "ofp_defines.h"

#if SOCKET
#include <errno.h>
#include <sys/socket.h>
#include "ofp_socket.h"
#include "ofp_workers.h"

#define DEFAULT_BIND_IP "127.0.0.1"
#define DEFAULT_BIND_PORT 9996
#define WELCOME_MSG "ofp_socket v1\n"

extern cpu_set_t dataplane_cpus; //TODO decl in ofp_main.h

static socket_message_cb_t socket_message_cb = NULL;
static socket_error_cb_t socket_error_cb = NULL;
static int bind_socket_desc = 0;

static pthread_t g_listenThread;

void* connection_close_on_error(int sock, const char* msg, const char* reason)
{
  if(socket_error_cb != NULL)
  {
    socket_error_cb(sock);
  }
  PRINT_D5("connection_close_on_error(%d) '%s' : '%s'\n", sock, msg, reason);
  close(sock);
  return NULL;
}

//The strcut describing the current state of socket data reading
typedef struct
{
  int sock;
  char* buffer;
  uint32_t buffer_size;
  char* data;
  char* data_end;
  int read_size;
} ofp_socket_info_t;

//return an error ofp_socket_info_t : .data field set to NULL & read_size <= 0 set from argument
ofp_socket_info_t ofp_socket_info_error(int read_size)
{
  ofp_socket_info_t res = { 0 };
  res.read_size = read_size;

  return res;
}

//return an error ofp_socket_info_t and close socket
ofp_socket_info_t ofp_socket_info_error_msg(ofp_socket_info_t info, const char* msg)
{
  PRINT_D5("connection_close_on_error(%d) '%s'\n", info.sock, msg);
  close(info.sock);

  ofp_socket_info_t res = { 0 };

  return res;
}

//check if ofp_socket_info_t is in error
int ofp_socket_info_has_error(ofp_socket_info_t info)
{
  return info.data == NULL;
}

//pull new data from socket
ofp_socket_info_t ofp_socket_recv_buffer(ofp_socket_info_t info)
{
  int read_size = recv(info.sock , info.buffer , info.buffer_size-1 , 0);
  if(read_size <= 0)
  {
    return ofp_socket_info_error(read_size);
  }
  info.data = info.buffer;
  info.data_end = info.data + read_size;
  info.data[read_size] = '\0';
  PRINT_D5("recv() size = %d\n", read_size);
  PRINT_D5("recv() data = '%s'\n", info.data);

  return info;
}

//fill dst with size bytes from socket
//will automatically pull as much data from socket as needed to fill size bytes
ofp_socket_info_t ofp_socket_read_to(ofp_socket_info_t info, void* dst, uint32_t size)
{
  char* dst_bytes = (char* )dst;
  OVH_ASSERT(size>0);
  if(size == 0) return ofp_socket_info_error_msg(info, "size == 0"); //check error

  int32_t remaining_data = info.data_end - info.data; //how many bytes are still in our internal buffer
  OVH_ASSERT(remaining_data>=0);
  if(remaining_data<0) return ofp_socket_info_error_msg(info, "remaining_data < 0"); //check error

  int32_t bytes_to_copy = size;

  while(bytes_to_copy>0) //there is still some bytes to copy
  {
    OVH_ASSERT(remaining_data>=0);
    if(remaining_data < 0) return ofp_socket_info_error_msg(info, "remaining_data < 0"); //check error
    if(remaining_data == 0) //no more enough remaining data in our internal buffer ?
    {
      info = ofp_socket_recv_buffer(info); //pull more data from socket
      if(ofp_socket_info_has_error(info)) return info; //check error
      remaining_data = info.data_end - info.data; //recompute how many data we have in our buffer
    }


    uint32_t copy_count = OVH_MIN(remaining_data, bytes_to_copy); //copy needed bytes, or only what's remaining in our buffer
    for (int i = 0; i < copy_count; ++i)
    {
      dst_bytes[i] = info.data[i];
    }
    //update ptr & counts
    dst_bytes += copy_count;
    info.data += copy_count;
    remaining_data -= copy_count;
    bytes_to_copy -= copy_count;
  }


  return info;
}

/*
 * This will handle connection for each client
 * */
void *connection_handler(void *socket_desc)
{
  // Set thread's tile
  if (tmc_cpus_set_my_cpu(tmc_cpus_find_nth_cpu(&dataplane_cpus, work_size)) < 0)
    TMC_TASK_DIE("Failure in 'tmc_cpus_set_my_cpu()'.");

  //Get the socket descriptor
  int sock = *(int*)socket_desc;
  char recv_message[2048];
  char command[256*1024];

  ssize_t writeRes = write(sock , WELCOME_MSG , strlen(WELCOME_MSG));
  if(writeRes<0) return connection_close_on_error(sock, "write() failed", strerror(errno));

  ofp_socket_info_t info = { 0 };
  info.sock = sock;
  info.buffer = recv_message;
  info.buffer_size = sizeof(recv_message);

  info = ofp_socket_recv_buffer(info); //pull data from socket (blocking)

  //Received a message from client
  while( !ofp_socket_info_has_error(info) )
  {
    //hard coded 'exit' command helper (for telnet test)
    if(strncmp(info.buffer, "exit", strlen("exit")) == 0)
    {
      PRINT_D5("'exit' command received, disconnecting client...\n");
      close(sock);
      info = ofp_socket_info_error(0);
      break;
    }

    uint32_t command_len = 0;
    //read command_len
    {
      info = ofp_socket_read_to(info, &command_len, sizeof(command_len));
      command_len = ntohl(command_len); //convert endianess
      if(ofp_socket_info_has_error(info)) break; //check for error

      PRINT_D5("command_len = %d\n", command_len);
    }

    //read command
    if(command_len > 0)
    {
      if(command_len>sizeof(command)-1) return connection_close_on_error(sock, "command size too big", ""); //check for error
      //we need to read command_len bytes from socket
      info = ofp_socket_read_to(info, command, command_len);
      command[command_len] = '\0'; //string term
      if(command_len>1 && command[command_len-1]=='\n') command[command_len-1] = '\0'; //remove trailing '\n' if present
      if(ofp_socket_info_has_error(info)) break; //check for error
      PRINT_D5("command = '%s'\n", command);
    }

    //process command
    {
      int ok = 1;
      if(socket_message_cb != NULL)
      {
        if(!socket_message_cb(sock, command))
        {
          ok = 0;
        }
      }

      if(!ok)
      {
        PRINT_D5("Disconnecting client...\n");
        close(sock);
        info = ofp_socket_info_error(0);
        break;
      }
    }
  }


  if(info.read_size == 0)
  {
    PRINT_D5("Client disconnected\n");
  }
  else if(info.read_size < 0)
  {
    return connection_close_on_error(sock, "recv() failed", strerror(errno));
  }
  close(sock);

  return NULL;
}

void* socket_run(void* arg)
{

  // Set thread's tile
  if (tmc_cpus_set_my_cpu(tmc_cpus_find_nth_cpu(&dataplane_cpus, work_size)) < 0)
    TMC_TASK_DIE("Failure in 'tmc_cpus_set_my_cpu()'.");

  PTHREAD_BARRIER_WAIT(work_barrier);
  PTHREAD_BARRIER_WAIT(work_barrier);

  PRINT_D5("[Socket] Starting\n");

  int client_sock , c;
  struct sockaddr_in server , client;

  //Create socket
  bind_socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (bind_socket_desc == -1)
  {
    PRINT_ERR("Could not create socket\n");
  }
  int optval = 1;
  setsockopt(bind_socket_desc, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)); //enable SO_REUSEADDR so bind will not fail in case of daemon restarting

  PRINT_D5("Socket created\n");

  //Prepare the sockaddr_in structure
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(DEFAULT_BIND_IP);
  //server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons( DEFAULT_BIND_PORT );

  //Bind
  if( bind(bind_socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
  {
    //print the error message
    PRINT_ERR("bind failed : '%s'\n", strerror(errno));
    return NULL;
  }
  PRINT_D5("bind done\n");

  //Listen
  listen(bind_socket_desc , 3);

  //Accept and incoming connection
  PRINT_D5("Waiting for incoming connections...\n");
  c = sizeof(struct sockaddr_in);
  pthread_t thread_id;

  while( (client_sock = accept(bind_socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
  {
    PRINT_D5("Connection accepted\n");

    if( pthread_create( &thread_id , NULL ,  connection_handler , (void*) &client_sock) < 0)
    {
      PRINT_ERR("could not create thread\n");
      return NULL;
    }

    //Now join the thread , so that we dont terminate before the thread
    //pthread_join( thread_id , NULL);
    PRINT_D5("Handler assigned\n");
  }

  if (client_sock < 0)
  {
    PRINT_ERR("accept failed : '%s'\n", strerror(errno));
    return NULL;
  }

  PRINT_D2("[Socket] Stoping\n");
  pthread_exit(0);
  return NULL;
}

//-------------------------------------------------------------------------------------------
// SIGPIPE handler
//-------------------------------------------------------------------------------------------
void sigpipe_handler(int sig)
{
  fprintf(stderr, "Received SIGPIPE (signal %d)\n", sig);
}
//-------------------------------------------------------------------------------------------

void socket_stop()
{
  PRINT_D5("socket_stop called on %d\n", bind_socket_desc);
  close(bind_socket_desc);
  pthread_cancel(g_listenThread);
  pthread_join(g_listenThread, NULL);
}

void socket_start(socket_message_cb_t message_cb, socket_error_cb_t error_cb)
{
  OVH_ASSERT(message_cb != NULL);
  OVH_ASSERT(error_cb != NULL);

  PRINT_D5("Installing SIGPIPE...\n");
  // Install SIGPIPE handler
  signal(SIGPIPE, sigpipe_handler);

  socket_message_cb = message_cb;
  socket_error_cb = error_cb;

  // Create a thread
  if (pthread_create(&g_listenThread, NULL, socket_run, NULL))
        TMC_TASK_DIE("pthread_create failed for socket_run.");

}


#endif //SOCKET
