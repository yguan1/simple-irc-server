/*
 *
 *  chirc: a simple multi-threaded IRC server
 *
 *  This module provides data structure that stores server information
 *  as well as functions creating and running server
 *
 */

#ifndef SERVER_H_
#define SERVER_H_

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

/* max string length of version */
#define MAX_VER_LENGTH 20
/* max string length of time */
#define TIME_LENGTH 20
#define STR_VALUE(arg) #arg
#define SERVER_VERSION STR_VALUE(3.14.15)
/* max string length of server name */
#define SERVER_STR_SZ 50
/* max string length of port number */
#define PORT_STR_SZ 10
/* max string length of server password */
#define PASSWD_STR_SZ 20

#include "connection.h"
#include "user.h"
#include "channel.h"
#include "message.h"
#include "server_network.h"

/* NOTE these may be changed to server_group in p1c */

/* Forward declaration */
typedef struct connection connection_t;
typedef struct channel channel_t;
typedef struct user user_t;
typedef struct remote_server remote_server_t;

typedef struct network_spec
{
    /* servername: server name specified in network file */
    char servername[SERVER_STR_SZ];
    /* hostname: host name specified in network file */
    char hostname[HOST_STR_SZ];
    /* port: port specified in network file */
    char port[PORT_STR_SZ];
    /* passwd: password specified in network file */
    char passwd[PASSWD_STR_SZ];

    UT_hash_handle hh;
} network_spec_t;

typedef struct server
{
    /* ===== START OF FIELDS PROTECTED BY SERVER_LOCK ===== */

    /* server_lock: mutex that locks server related fields */
    pthread_mutex_t server_lock;

    /* version: server version */
    char version[MAX_VER_LENGTH];

    /* time_created: time when the server was created */
    char time_created[TIME_LENGTH];

    /* port: the port this server is running on */
    char *port;

    /* passwd: OPERATOR passwd when creating server, used when adding operator*/
    char *passwd;

    /* connection_passwd: passwd read from network file, used when connected by
     * other remote servers */
    char *connection_passwd;

    /* server_name: name of the server */
    char *server_name;

    /* network_file: network file input when creating server.
     * Must specify servername if this is specified */
    char *network_file;

    /* network_spec: content of the network file parsed and stored
     * in a hashtable */
    network_spec_t *network_spec;

    /* server_hostname: the host where server is running on */
    char *server_hostname;

    /* server_socket: the passive listening socket the server is using */
    int server_socket;

    /* ===== END OF FIELDS PROTECTED BY SERVER_LOCK ===== */


    /* ===== START OF FIELDS PROTECTED BY USER_LOCK ===== */

    /* user_lock: mutex that locks user related fields */
    pthread_mutex_t user_lock;

    /* all_users: a hash table of all users where nickname is the key */
    user_t *all_users;

    /* num_user_registered: number of total registered users
     * (should be size of all_users minus only-nickname-known users) s*/
    int num_user_registered;

    /* num_operator: number of operators */
    int num_operator;

    /* ===== END OF FIELDS PROTECTED BY USER_LOCK ===== */


    /* ===== START OF FIELDS PROTECTED BY CHANNEL_LOCK ===== */

    /* channel_lock: mutex that locks channel related fields */
    pthread_mutex_t channel_lock;

    /* all_channels: a hash table of all channels where channel name is the key */
    channel_t *all_channels;

    /* ===== END OF FIELDS PROTECTED BY CHANNEL_LOCK ===== */


    /* ===== START OF FIELDS PROTECTED BY CONNECTION_LOCK ===== */

    /* connection_lock: mutex that locks connection related fields */
    pthread_mutex_t connection_lock;

    /* num_total_connection: number of total connections */
    int num_total_connection;

    /* num_user_connection: number of user connections */
    int num_user_connection;

    /* num_server_connection: number of server connections */
    int num_server_connection;

    /* ===== END OF FIELDS PROTECTED BY CONNECTION_LOCK ===== */


    /* ===== START OF FIELDS PROTECTED BY REMOTE_SERVER_LOCK ===== */

    /* remote_server_lock: mutex that locks remote_server related fields */
    pthread_mutex_t remote_server_lock;

    /* all_remote_servers: a hash table of all remote_servers where servername is the key */
    remote_server_t *all_remote_servers;

    /* ===== END OF FIELDS PROTECTED BY REMOTE_SERVER_LOCK ===== */
} server_t;

typedef struct server_wa
{
    /* port: the port this server is running on */
    char *port;

    /* passwd: password input when creating server, used when adding operator*/
    char *passwd;

    /* server_name: name of the server */
    char *server_name;

    /* network_file: network file input when creating server.
     * Must specify servername if this is specified */
    char *network_file;
} server_wa_t;

/* create_server - create a new server with given args,
 * listening socket being set up
 *
 * server_wa: pointer to server working args that were specified when creating
 * server, which include port, passwd, servername, and network_file
 *
 * Returns: a pointer to a new server struct with all mutexes initiated
 */
server_t *create_server(server_wa_t *server_wa);

/* run_server - run a given server by listening to connections.
 * Once a connection is accepted, a separate thread is created to serve it.
 *
 * server: a pointer to a created server struct
 *
 * Returns: none
 */
void run_server(server_t *server);

/* send_string_to_server - send a string to all users in the server
 *
 * server: the server the string is sent to
 *
 * str: the string to sent
 *
 * skipped_user: a user that the server doesn't send a message to (e.g. sender) OK even if it's NULL
 *
 * Returns: 0 if success; 1 if error
 */
int send_string_to_server(server_t *server, char* str, user_t *skipped_user);

/* delete_server - frees the space malloced for the server
 *
 * server: the pointer to the server
 *
 * Returns: none
 */
void delete_server(server_t *server);

/* parse_network_file - parse network file and store in server
 * 
 * server: the server we are running
 * 
 * Returns: 0 if success; 1 if error
 */
int parse_network_file(server_t *server);

/* find_network_spec - find a specific network_spec_t
 * 
 * local_server: the server we are running
 * 
 * servername: name of the network_spec_t we are finding
 * 
 * Return: the target network_spec_t
 */
network_spec_t *find_network_spec(server_t *local_server, char *servername);

#endif