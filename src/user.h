/*
 *
 *  chirc: a simple multi-threaded IRC server
 *
 *  This module provides the data structure that stores user information,
 *  and includes relevant utility functions.
 *
 */

#ifndef USER_H_
#define USER_H_

#include <stdbool.h>

#include "utlist.h"
#include "uthash.h"
#include "log.h"

/* max string length of hostname */
#define HOST_STR_SZ 510
/* max string length of service name */
#define SERVICE_STR_SZ 20
/* max string length of nickname */
#define NICK_STR_SZ 20
/* max string length of username */
#define USER_STR_SZ 20
/* max number of user */
#define MAX_USER_NUM 200

#include "connection.h"
#include "channel.h"
#include "server.h"

/* Forward declaration */
typedef struct server server_t;
typedef struct connection connection_t;
typedef struct channel channel_t;
typedef struct channel_hash channel_hash_t;

typedef struct user
{
    /* user_lock: mutex that locks an individual user */
    pthread_mutex_t user_lock_individual;

    /* nickname: user's nickname */
    /* This is the key of the hashtable */
    char nickname[NICK_STR_SZ];

    /* username: user's username */
    char username[USER_STR_SZ];

    /* realname: user's real name */
    char realname[USER_STR_SZ];

    /* hostname: user's hostname */
    char hostname[HOST_STR_SZ];

    /* servname: user's service name */
    char servname[SERVICE_STR_SZ];

    /* is_registered: is the user registered */
    bool is_registered;

    /* is_irc_op: is the user an IRC operator */
    bool is_irc_op;

    /* connection_to_server: link back to the connection
     * where socket info is stored */
    connection_t *connection_to_server;

    /* connected_server_name: name of the server this user is connected to */
    char connected_server_name[SERVER_STR_SZ];

    /* user_channels: hashtable that record all the channel this user is in */
    channel_hash_t *user_channels;

    UT_hash_handle hh;
} user_t;

/* wrap the user struct and put a hash_handle along with it
 * so that it can be added to multiple hash tables */
typedef struct user_hash
{
    user_t *user;

    /* key in the hashtable */
    char name[NICK_STR_SZ];

    UT_hash_handle hh;
} user_hash_t;

/* create_user - create user_t struct
 *
 * connection: link back to the connection that corresponds to this
 * user (use NULL if connection not known (should not happen though))
 *
 * Returns: an empty user struct with everything but connection_to_server
 * set as default
 */
user_t *create_user(connection_t *connection);

/* add_user_to_server - add a user to a server, updated version of add_user
 *
 * server: the server to be added to
 *
 * user: the user to be added
 *
 * Returns: 0 if success, 1 if error
 */
int add_user_to_server(server_t *server, user_t *user);

/* num_users - count the number of registered users
 *
 * all_users: the pointer to the data structure of all users
 *
 * Returns: the number of users in the hashtable
 */
int num_users(user_t *all_users);

/* find_user - get user struct by user nickname (key)
 *
 * all_users: the pointer to the data structure of all users
 *
 * nickname: the nickname of the user we are looking for
 *
 * Returns: the user struct corresponding to the nickname
 */
user_t *find_user(user_t *all_users, char *nickname);

/* delete_user - remove user struct from the data structure (hashtable)
 * where all users are stored
 * note that this function DOESN'T FREE THE USER STRUCT
 *
 * all_users: the pointer to the pointer to the data structure of all users
 * (important! two layers of pointers!)
 *
 * user: the pointer to the user struct to be deleted
 *
 * Returns: 0 if success, 1 if error
 */
int delete_user(user_t **all_users, user_t *user);

/* send_string_to_user - send a string to a specific user
 *
 * user: the user the string is sent to
 *
 * str: the string to sent
 *
 * Returns: 0 if success; 1 if error
 */
int send_string_to_user(user_t *user, char* str);

#endif