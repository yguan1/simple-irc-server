/*
 *
 *  chirc: a simple multi-threaded IRC server
 *
 *  This module includes the stuct and utility functions
 *  related to the IRC server network
 *
 */
/*
 *  Copyright (c) 2011-2020, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef SERVER_NETWORK_H_
#define SERVER_NETWORK_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

#include "utlist.h"
#include "uthash.h"
#include "log.h"

#include "connection.h"
#include "user.h"
#include "server.h"
#include "channel.h"
#include "message.h"

/* Forward declaration */
typedef struct connection connection_t;
typedef struct server server_t;

typedef struct remote_server
{
    /* remote_server_lock: mutex of a remote_server struct (local info) */
    pthread_mutex_t remote_server_lock_individual;

    /* servername: the remote server's server name */
    char servername[SERVER_STR_SZ];

    /* the connection back the local server */
    /* if remote does not directly connect to the local server,
     * connection_to_local is then NULL */
    connection_t *connection_to_local;

    /* rcvd_password: password received from PASS command */
    char rcvd_password[PASSWD_STR_SZ];

    /* is_registered: is the server registered */
    bool is_registered;

    /* is_passive: is the server the passive server we are connecting to */
    bool is_passive;

    UT_hash_handle hh;

} remote_server_t;

/* connect_remote_server - try to connect to another server; if success, will
 * establish a connection between the two servers
 * NOTE: this function will create a remote_server struct as well as a connection struct that point to each other; this is intended for the server actively trying to connect another
 * NOTE: remember to put the returned remote_server_t (you can find it inside the connection_t) into all_remote_servers
 *
 * local_server: the active server
 * 
 * target_server_name: server name of the passive server
 * 
 * Returns: 0 if success, 1 if error
 */
int connect_remote_server(server_t *local_server, char *target_server_name);

/* create_remote_server - create remote_server_t struct
 * NOTE: when a server actively connect another server, this function is not required; instead, use connect_remote_server
 *
 * connection: link back to the connection that corresponds to this
 * remote_server (use NULL if connection not known (should not happen though))
 *
 * Returns: an empty remote_server struct with everything but connection_to_server
 * set as default
 */
remote_server_t *create_remote_server(connection_t *connection);

/* add_remote_server_to_server - add a remote_server to a server, updated version of add_remote_server
 *
 * server: the server to be added to
 *
 * remote_server: the remote_server to be added
 *
 * Returns: 0 if success, 1 if error
 */
int add_remote_server_to_server(server_t *server, remote_server_t *remote_server);

/* num_remote_servers - count the number of registered remote_servers
 *
 * all_remote_servers: the pointer to the data structure of all remote_servers
 *
 * Returns: the number of remote_servers in the hashtable
 */
int num_remote_servers(remote_server_t *all_remote_servers);

/* find_remote_server - get remote_server struct by remote_server servername (key)
 *
 * all_remote_servers: the pointer to the data structure of all remote_servers
 *
 * servername: the servername of the remote_server we are looking for
 *
 * Returns: the remote_server struct corresponding to the servername
 */
remote_server_t *find_remote_server(remote_server_t *all_remote_servers, char *servername);

/* delete_remote_server - remove remote_server struct from the data structure (hashtable)
 * where all remote_servers are stored
 * note that this function DOESN'T FREE THE remote_server STRUCT
 *
 * all_remote_servers: the pointer to the pointer to the data structure of all remote_servers
 * (important! two layers of pointers!)
 *
 * remote_server: the pointer to the remote_server struct to be deleted
 *
 * Returns: 0 if success, 1 if error
 */
int delete_remote_server(remote_server_t **all_remote_servers, remote_server_t *remote_server);

/* send_string_to_remote_server - send a string to a specific remote_server
 *
 * remote_server: the remote_server the string is sent to
 *
 * str: the string to sent
 *
 * Returns: 0 if success; 1 if error
 */
int send_string_to_remote_server(remote_server_t *remote_server, char* str);

/* send_string_to_all_remote_servers - send a string to all remote servers
 * 
 * local_server: the server who is sending string
 * 
 * str: the string to be sent
 * 
 * Returns: 0 if success; 1 if error
 */
int send_string_to_all_remote_servers(server_t *local_server, char *str);

#endif