#ifndef CONNECTION_H_
#define CONNECTION_H_

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

#include "user.h"
#include "server.h"
#include "message.h"
#include "handler.h"
#include "server_network.h"

/* Forward declaration */
typedef struct server server_t;
typedef struct channel channel_t;
typedef struct user user_t;
typedef struct remote_server remote_server_t;

enum connection_type {Unknown, User, Server};

typedef struct connection
{
    /* connection_socket_lock: mutex that locks a socket
     * to prevent two threads sending to one user at the same time */
    pthread_mutex_t connection_socket_lock;

    /* type: connection type is either User or Server */
    enum connection_type type;

    /* server: the server this connection is on */
    server_t *server;

    /* socket: the active socket on the server side that
     * corresponds to a connection */
    int socket;

    /* The connection will be either User or Server,
     * and the other one should be NULL */

    /* connected_user: the user this connection is connected to */
    user_t *connected_user;

    /* connected_remote_server: the remote server this connection is connected to */
    /* specifically, this struct records the servername and the local connection struct */
    remote_server_t *connected_remote_server;

} connection_t;

typedef struct worker_args_t
{
    /* connection: the connection that the thread plays with */
    connection_t *connection;

} worker_args_t;

/* create_connection - create a connection that connects to a
 * user/another server
 *
 * type: an enum connection_type value (user/server)
 *
 * server: the server which the connection is created on
 *
 * socket: active socket on the server side that connects to the
 * user/another server
 *
 * Returns: a connection struct
 */
connection_t *create_connection(enum connection_type type, server_t *server, int socket);

/* service_single_connection - function which serves for a single client;
 * will be used for the routine function of a thread
 *
 * ctx: the server context that stores basic informations like all_users
 *
 * args: worker args struct wa (specified below) that is
 * cast to void*
 *
 * wa: a worker struct that contains only connection_info, which is
 * a connection this thread/service is working on
 *
 * Returns: none
 */
void *service_single_connection(void *args);

/* get_full_msgstr - Get a full length message string via a connected socket
 *
 * client_socket: a connected socket from which we will get the message
 *
 * buffer: a full-message-size(MAX_IRC_MSG_LEN + 3) string
 * that stores the received message
 *
 * res: a full-message-size(MAX_IRC_MSG_LEN + 3) string; message received will
 * be stored here and returned; it will be cleared before returning
 *
 * Returns: 0 if success; 1 if error getting a message
 */
int get_full_msgstr(int client_socket, char **buffer_ptr, char *res);

/* send_all - an updated version of send(), which ensures that the whole
 * string will be sent by one call of send_all()
 *
 * socket: the socket to send, same as send()
 *
 * str: the string to send, same as send()
 *
 * length: the length of the string, same as send()
 *
 * flags: the flags, same as send()
 *
 * returns: true if whole string sent successfully; false if an error occurs
 */
bool send_all(int socket, void *str, size_t length, int flags);

#endif