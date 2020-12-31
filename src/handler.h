/*
 *
 *  chirc: a simple multi-threaded IRC server
 *
 *  This module provides function that handles IRC commands
 *
 */

#ifndef HANDLER_H_
#define HANDLER_H_

#include "log.h"
#include "server.h"
#include "connection.h"
#include "message.h"
#include "server_network.h"

/* Forward declaration from server.h */
typedef struct server server_t;

/* handle_command - handle IRC message with commands
 *
 * server: the server we are running on
 *
 * conn: the connection of which the command we are handling
 *
 * msg: the message with command we need to handle
 *
 * Returns: 0 if successed, 1 if error occured
 */
int handle_command(server_t *server, connection_t *conn, message_t *msg);

#endif