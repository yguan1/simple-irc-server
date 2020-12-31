/*
 *
 *  chirc: a simple multi-threaded IRC server
 *
 *  This module provides the data structure that stores channel information,
 *  and includes relevant utility functions.
 *
 */

#ifndef CHANNEL_H_
#define CHANNEL_H_

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

#include "utlist.h"
#include "uthash.h"
#include "log.h"

#include "connection.h"
#include "user.h"
#include "server.h"

/* max string length of channel name */
#define MAX_CHANNEL_STR_SZ 20
/* max number of channels */
#define MAX_CHANNEL_NUM 100

/* Forward declaration */
typedef struct server server_t;
typedef struct connection connection_t;
typedef struct user user_t;
typedef struct user_hash user_hash_t;

typedef struct channel
{
    /* channel_lock: mutex that locks an individual channel */
    pthread_mutex_t channel_lock_individual;

    /* channel_name: channel name */
    char channel_name[MAX_CHANNEL_STR_SZ];

    /* channel_users: a hashtable of all users in this channel */
    user_hash_t *channel_users;

    UT_hash_handle hh;

} channel_t;

/* wrap the channel struct and put a hash_handle along with it
 * so that it can be added to multiple hash tables */
typedef struct channel_hash
{
    /* the real channel struct */
    channel_t *channel;

    /* key in the hashtable */
    char name[MAX_CHANNEL_STR_SZ];

    /* record whether the user is operator of this channel */
    /* it has to be put here in a wrap as users may join multiple channels */
    bool is_channel_op;

    UT_hash_handle hh;
} channel_hash_t;

/* create_channel - create channel_t struct and
 * add it to the data structure of all channels
 *
 * channel_name: name of the channel to be created
 *
 * Returns: an empty channel_t struct with everything but channel_name
 * set as default
 */
channel_t *create_channel(char *channel_name);

/* add_channel_to_server - add a channel to a server, updated version of add_channel
 *
 * server: the server to be added to
 *
 * channel: the channel to be added
 *
 * Returns: 0 if success, 1 if error
 */
int add_channel_to_server(server_t *server, channel_t *channel);

/** add_user_to_channel - add a user to a channel
 *
 * channel: a pointer to a channel to be added to
 *
 * user: a pointer to a user to be added
 *
 * Returns: 0 if success; 1 if error
 */
int add_user_to_channel(channel_t *channel, user_t *user);

/* num_channels - count the number of channels
 *
 * all_channels: the pointer to the data structure of all channels
 *
 * Returns: the number of channels in the hashtable
 */
int num_channels(channel_t *all_channels);

/* find_channel - get channel struct by channel name (key)
 *
 * all_channels: the pointer to the data structure of all channels
 *
 * channel_name: the name of the channel we are looking for
 *
 * Returns: the channel struct corresponding to the name
 */
channel_t *find_channel(channel_t *all_channels, char *channel_name);

/* delete_channel_from_server - remove channel struct from the server
 * where all channels are stored
 *
 * all_channels: the pointer to the data structure of all channels
 *
 * channel: the pointer to the channel struct to be deleted
 *
 * Returns: 0 if success, 1 if error
 */
int delete_channel_from_server(server_t *server, channel_t *channel);

/* list_users_in_channel - list all users in channel in string
 *
 * channel: the channel needs to list
 *
 * Returns: a string of all users' nicknames, separated by spaces
 */
char *list_users_in_channel(channel_t *channel);

/* send_string_to_channel - send a string to all users in the channel (used in PRIVMSG and NOTICE)
 *
 * channel: the channel the string is sent to
 *
 * str: the string to sent
 *
 * skipped_user: a user that the server doesn't send a message to (e.g. sender) OK even if it's NULL
 *
 * Returns: 0 if success; 1 if error
 */
int send_string_to_channel(channel_t *channel, char* str, user_t *skipped_user);

/* list_user_channels - list all channels the user is in
 *
 * user: the user whose channels needs to be listed
 *
 * Returns: a string of all channels' names
 */
char *list_user_channels(user_t *user);

/* is_user_in_channel - check if a given user is in a given channel
 *
 * channel: the pointer to the channel struct
 *
 * user: the pointer to the user struct
 *
 * Returns: true if user is in channel, false if not
 */
bool is_user_in_channel(channel_t *channel, user_t *user);

/* add_user_to_channel_ops - give a user channel operator privilege
 *
 * channel: the pointer to the channel struct
 *
 * user: the pointer to the user struct
 *
 * Returns: 0 if success; 1 if error
 */
int add_user_to_channel_ops(channel_t *channel, user_t *user);

/* rm_user_from_channel_ops - remove a user's channel operator privilege
 *
 * channel: the pointer to the channel struct
 *
 * user: the pointer to the user struct
 *
 * Returns: 0 if success; 1 if error
 */
int rm_user_from_channel_ops(channel_t *channel, user_t *user);

/* is_user_channel_op - check if a given user is an operator of a given channel
 *
 * channel: the pointer to the channel struct
 *
 * user: the pointer to the user struct
 *
 * Returns: true if user is an operator, false if not
 */
bool is_user_channel_op(channel_t *channel, user_t *user);

/* delete_user_from_channel - delete a user from a channel
 * This will update both the channel list of the user
 * and the user list of the channel
 *
 * channel: the pointer to the channel struct
 *
 * user: the pointer to the user struct
 *
 * Returns: 0 if success; 1 if error
 */
int delete_user_from_channel(channel_t *channel, user_t *user);

/* num_users_in_channel - count the number of users in a specific channel
 *
 * channel: the pointer to the channel struct
 *
 * Returns: number of users in the given channel
 */
int num_users_in_channel(channel_t *channel);

/* send_string_to_user_channels - send string to all channels a user is in
 *
 * user: the user who's channels we are sending to
 *
 * str: the string we are sending
 *
 * Returns: number of users in the given channel
 */
int send_string_to_user_channels(user_t *user, char *str);

#endif