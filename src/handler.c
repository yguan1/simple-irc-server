#include "handler.h"
#include "reply.h"
#include "message.h"
#include "channel.h"

/* register_user - register a user with nickname and username
 *
 * server: the server we are running on
 *
 * user: the user whose command we need to handle
 *
 * msg: the message with command we need to handle
 *
 * Returns: 0 if success, 1 if error
 */
int register_user(server_t *server, user_t *user, message_t *msg);

/* register_server - register a server with password and server name
 *
 * server: the server we are running on
 *
 * remote_server: the remote server whose command we need to handle
 *
 * Returns: 0 if success, 1 if error
 */
int register_server(server_t *server, remote_server_t *remote_server);

/* send_privmsg_to_user - relay PRIVMSG or NOTICE to another user
 *
 * server: the server we are running on
 *
 * user: the user who send the message
 *
 * target_user: the user who is going to receive the message
 *
 * rcvd_msg: the message with command we need to handle
 *
 * Returns: 0 if success, 1 if error
 */
int send_privmsg_to_user(server_t *server, user_t *user, user_t *target_user, message_t *rcvd_msg);

/* send_channel_info - send channel info to a user (used when parsing LIST with parameter)
 *
 * channel: the channel of which the info we are sending
 *
 * user: the user who is going to receive the message
 *
 * Returns: 0 if success, 1 if error
 */
int send_channel_info(channel_t *channel, user_t *user);

/* send_join_to_channel - relay JOIN message to channel
 *
 * server: the server we are running on
 *
 * user: the user who send the message
 *
 * rcvd_msg: the message with command we need to handle
 *
 * Returns: 0 if success, 1 if error
 */
int change_user_nick(server_t *server, user_t *user, message_t *rcvd_msg);

/* send_nick_to_servers - send NICK message to remote servers when a user register
 *
 * server: the server we are running on
 *
 * user: the user who is registered
 *
 * Returns: 0 if success, 1 if error
 */
int send_nick_to_servers(server_t *server, user_t *user);

/* send_string_to_remote_servers - send string to all remote servers
 *
 * server: the server we are running on
 *
 * str: the string we are sending
 *
 * Returns: 0 if success, 1 if error
 */
int send_string_to_remote_servers(server_t *server, char *str);

/* relay_command_to_servers - relay commands to all remote servers
 *
 * server: the server we are running on
 *
 * user: the user who sent the original message
 * 
 * msg: the message to be relayed
 *
 * Returns: 0 if success, 1 if error
 */
int relay_command_to_servers(server_t *server, user_t *user, message_t *msg);

/* send_part_to_channel - relay PART message to channel
 *
 * server: the server we are running on
 *
 * user: the user who send the message
 *
 * target_channel: the channel which is going to receive the message
 *
 * rcvd_msg: the message with command we need to handle
 *
 * Returns: 0 if success, 1 if error
 */
int send_part_to_channel(server_t *server, user_t *user, channel_t *target_channel, message_t *rcvd_msg);

/* send_quit_message - relay QUIT message to channel
 *
 * server: the server we are running on
 *
 * user: the user who send the message
 *
 * rcvd_msg: the message with command we need to handle
 *
 * Returns: 0 if success, 1 if error
 */
int send_quit_message(server_t *server, user_t *user, message_t *rcvd_msg);

/* send_cmd_to_channel - relay commands to channel
 *
 * server: the server we are running on
 *
 * user: the user who send the message
 *
 * target_channel: the channel which is going to receive the message
 *
 * rcvd_msg: the message with command we need to handle
 *
 * Returns: 0 if success, 1 if error
 */
int send_cmd_to_channel(server_t *server, user_t *user, channel_t *target_channel, message_t *rcvd_msg);

/* user_handle_CMD - handle functions that handle specific commands from user
 *
 * server: the server we are running on
 *
 * user: the user whose command we need to handle
 *
 * msg: the message with command we need to handle
 *
 * Returns: 0 if success, 1 if error
 */
int user_handle_NICK(server_t *server, user_t *user, message_t *msg);
int user_handle_USER(server_t *server, user_t *user, message_t *msg);
int user_handle_QUIT(server_t *server, user_t *user, message_t *msg);
int user_handle_PONG(server_t *server, user_t *user, message_t *msg);
int user_handle_PING(server_t *server, user_t *user, message_t *msg);
int user_handle_LUSERS(server_t *server, user_t *user, message_t *msg);
int user_handle_WHOIS(server_t *server, user_t *user, message_t *msg);
int user_handle_JOIN(server_t *server, user_t *user, message_t *msg);
int user_handle_PRIVMSG(server_t *server, user_t *user, message_t *msg);
int user_handle_NOTICE(server_t *server, user_t *user, message_t *msg);
int user_handle_MODE(server_t *server, user_t *user, message_t *msg);
int user_handle_OPER(server_t *server, user_t *user, message_t *msg);
int user_handle_PART(server_t *server, user_t *user, message_t *msg);
int user_handle_LIST(server_t *server, user_t *user, message_t *msg);
int user_handle_CONNECT(server_t *server, user_t *user, message_t *msg);

/* server_handle_CMD - handle functions that handle specific commands from server
 *
 * server: the server we are running on
 *
 * remote_server: the server whose command we need to handle
 *
 * msg: the message with command we need to handle
 *
 * Returns: 0 if success, 1 if error
 */
int server_handle_NICK(server_t *server, remote_server_t *remote_server, message_t *msg);
int server_handle_PASS(server_t *server, remote_server_t *remote_server, message_t *msg);
int server_handle_SERVER(server_t *server, remote_server_t *remote_server, message_t *msg);
int server_handle_PRIVMSG(server_t *server, remote_server_t *remote_server, message_t *msg);
int server_handle_JOIN(server_t *server, remote_server_t *remote_server, message_t *msg);

/* handle_user_command - handle user message with commands
 *
 * server: the server we are running on
 *
 * user: the user whose command we need to handle
 *
 * msg: the message with command we need to handle
 *
 * Returns: 0 if successed, 1 if error occured
 */
int handle_user_command(server_t *server, user_t *user, message_t *msg);

/* handle_server_command - handle server message with commands
 *
 * server: the server we are running on
 *
 * remote_server: the remote server whose command we need to handle
 *
 * msg: the message with command we need to handle
 *
 * Returns: 0 if successed, 1 if error occured
 */
int handle_server_command(server_t *server, remote_server_t *remote_server, message_t *msg);

typedef int (*user_handler_function)(server_t *server, user_t *user, message_t *msg);
typedef int (*server_handler_function)(server_t *server, remote_server_t *remote_server, message_t *msg);

struct user_handler_entry
{
    char *name;
    user_handler_function func;
};

struct server_handler_entry
{
    char *name;
    server_handler_function func;
};

#define USER_HANDLER_ENTRY(NAME) { #NAME, user_handle_ ## NAME}
#define SERVER_HANDLER_ENTRY(NAME) { #NAME, server_handle_ ## NAME}

struct user_handler_entry user_handlers[] = {
                                     USER_HANDLER_ENTRY(NICK),
                                     USER_HANDLER_ENTRY(USER),
                                     USER_HANDLER_ENTRY(QUIT),
                                     USER_HANDLER_ENTRY(PING),
                                     USER_HANDLER_ENTRY(PONG),
                                     USER_HANDLER_ENTRY(LUSERS),
                                     USER_HANDLER_ENTRY(WHOIS),
                                     USER_HANDLER_ENTRY(OPER),
                                     USER_HANDLER_ENTRY(JOIN),
                                     USER_HANDLER_ENTRY(PRIVMSG),
                                     USER_HANDLER_ENTRY(NOTICE),
                                     USER_HANDLER_ENTRY(MODE),
                                     USER_HANDLER_ENTRY(PART),
                                     USER_HANDLER_ENTRY(LIST),
                                     USER_HANDLER_ENTRY(CONNECT)
                                  };

struct server_handler_entry server_handlers[] = {
                                     SERVER_HANDLER_ENTRY(NICK),
                                     SERVER_HANDLER_ENTRY(PASS),
                                     SERVER_HANDLER_ENTRY(SERVER),
                                     SERVER_HANDLER_ENTRY(PRIVMSG),
                                     SERVER_HANDLER_ENTRY(JOIN)
                                  };

int handle_command(server_t *server, connection_t *conn, message_t *msg)
{
    int res;
    if (conn->type == User)
    {
        res = handle_user_command(server, conn->connected_user, msg);
        return res;
    }
    else if (conn->type == Server)
    {
        res = handle_server_command(server, conn->connected_remote_server, msg);
        return res;
    }
    else
    {
        /* if connection type is Unknown */
        /* we only accept NICK USER SERVER PASS */
        if (!strcmp(msg->cmd, "NICK"))
        {
            conn->type = User;
            chilog(DEBUG, "connection type changed to User");
            pthread_mutex_lock(&server->connection_lock);
            server->num_user_connection++;
            chilog(INFO, "num_user_connection increases to %d", server->num_user_connection);
            pthread_mutex_unlock(&server->connection_lock);
            user_handle_NICK(server, conn->connected_user, msg);
        }
        else if (!strcmp(msg->cmd, "USER"))
        {
            conn->type = User;
            chilog(DEBUG, "connection type changed to User");
            pthread_mutex_lock(&server->connection_lock);
            server->num_user_connection++;
            pthread_mutex_unlock(&server->connection_lock);
            chilog(INFO, "num_user_connection increases to %d", server->num_user_connection);
            user_handle_USER(server, conn->connected_user, msg);
        }
        else if (!strcmp(msg->cmd, "PASS"))
        {
            conn->type = Server;
            chilog(DEBUG, "connection type changed to Server");
            pthread_mutex_lock(&server->connection_lock);
            server->num_server_connection++;
            pthread_mutex_unlock(&server->connection_lock);
            server_handle_PASS(server, conn->connected_remote_server, msg);
        }
        else if (!strcmp(msg->cmd, "SERVER"))
        {
            conn->type = Server;
            chilog(DEBUG, "connection type changed to Server");
            pthread_mutex_lock(&server->connection_lock);
            server->num_server_connection++;
            pthread_mutex_unlock(&server->connection_lock);
            server_handle_SERVER(server, conn->connected_remote_server, msg);
        }
        else
        {
            res = handle_user_command(server, conn->connected_user, msg);
            return res;
        }
        return 0;
    }
}

int handle_user_command(server_t *server, user_t *user, message_t *msg)
{
    int i;
    int num_handlers = sizeof(user_handlers) / sizeof(struct user_handler_entry);

    for (i = 0; i < num_handlers; i++)
        if (!strcmp(user_handlers[i].name, msg->cmd))
        {
            int res = user_handlers[i].func(server, user, msg);
            return res;
        }
    /* note the the response to unknown command
     * is different for registered and unregistered users*/
    if (i == num_handlers)
    {
        if (user->is_registered)
        {
            send_response(ERR_UNKNOWNCOMMAND, server, user, msg);
            return 1;
        }
        else
        {
            chilog(DEBUG, "unknown command encounted while unregistered");
            return 1;
        }
    }
}

int handle_server_command(server_t *server, remote_server_t *remote_server, message_t *msg)
{
    int i;
    int num_handlers = sizeof(server_handlers) / sizeof(struct server_handler_entry);

    for (i = 0; i < num_handlers; i++)
        if (!strcmp(server_handlers[i].name, msg->cmd))
        {
            int res = server_handlers[i].func(server, remote_server, msg);
            return res;
        }
    if (i == num_handlers)
    {
        chilog(ERROR, "unknown command encountered");
    }
    return 0;
}

int user_handle_NICK(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "handling NICK");
    if (msg->nparams < 1)
    {
        send_response(ERR_NONICKNAMEGIVEN, server, user, msg);
        return 1;
    }
    char *nickname = msg->params[0];
    if (user->is_registered)
    {
        /* since nickname is the key of the hashtable
         * we delete the it from the hashtable and add it back
         * to make sure that it is safe */
        change_user_nick(server, user, msg);

        pthread_mutex_lock(&server->user_lock);
        delete_user(&server->all_users, user);
        pthread_mutex_unlock(&server->user_lock);

        /* update all the wraps that contain this user */
        channel_hash_t *curr_channel_wrapped, *tmp;
        user_hash_t *curr_user_wrapped;
        HASH_ITER(hh, user->user_channels, curr_channel_wrapped, tmp)
        {
            HASH_FIND_STR(curr_channel_wrapped->channel->channel_users,
                          user->nickname, curr_user_wrapped);
            strcpy(curr_user_wrapped->name, nickname);
        }

        strcpy(user->nickname, nickname);

        /* this is thread safe */
        add_user_to_server(server, user);

        chilog(TRACE, "successfully changed nick");

        return 0;
    }
    else
    {
        if (find_user(server->all_users, nickname) != NULL)
        {
            send_response(ERR_NICKNAMEINUSE, server, user, msg);
            return 1;
        }
        else
        {
            strcpy(user->nickname, nickname);
            /* check if user has username, if so, register user */
            if (strcmp(user->username, "") != 0)
            {
                register_user(server, user, msg);
            }
            return 0;
        }
    }
}

int user_handle_USER(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "handling USER");
    if (msg->nparams < 4)
    {
        send_response(ERR_NEEDMOREPARAMS, server, user, msg);
        return 1;
    }
    if (user->is_registered)
    {
        send_response(ERR_ALREADYREGISTRED, server, user, msg);
        return 1;
    }
    strcpy(user->username, msg->params[0]);
    strcpy(user->realname, msg->params[3]);
    chilog(TRACE, "username added to user: \"%s\"", msg->params[0]);
    chilog(TRACE, "real name added to user: \"%s\"", msg->params[3]);

    /* check if user has username, if so, register user */
    if (strcmp(user->nickname, "") != 0)
    {
        register_user(server, user, msg);
    }
    return 0;
}

int user_handle_QUIT(server_t *server, user_t *user, message_t *rcvd_msg)
{
    chilog(TRACE, "handling QUIT");
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, rcvd_msg);
        return 1;
    }

    message_t *msg = calloc(1, sizeof(message_t));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *long_param = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    int socket = user->connection_to_server->socket;
    pthread_mutex_lock(&server->connection_lock);
    server->num_user_connection--;
    server->num_total_connection--;
    pthread_mutex_unlock(&server->connection_lock);
    
    msg_construct(msg, server->server_name, "ERROR");
    if (rcvd_msg->nparams == 0)
    {
        sprintf(long_param, "Closing Link: %s (Client Quit)", user->hostname);
    }
    else
    {
        sprintf(long_param, "Closing Link: %s (%s)", user->hostname, rcvd_msg->params[0]);
    }
    msg_add_param(msg, long_param, true);
    msg_to_string(msg, &reply);
    chilog(INFO, "QUIT response successfully sent: %s", reply);
    /* send quit message to all channels */
    send_quit_message(server, user, rcvd_msg);
    /* send quit message to user */
    send_string_to_user(user, reply);
    close(socket);
    delete_user(&server->all_users, user);
    free(user);
    free(reply);
    free(long_param);
    msg_destroy(msg);

    return 1;
}

int user_handle_LUSERS(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "handling LUSERS");
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }
    send_response(RPL_LUSERCLIENT, server, user, msg);
    send_response(RPL_LUSEROP, server, user, msg);
    send_response(RPL_LUSERUNKNOWN, server, user, msg);
    send_response(RPL_LUSERCHANNELS, server, user, msg);
    send_response(RPL_LUSERME, server, user, msg);

    return 0;
}

int user_handle_PING(server_t *server, user_t *user, message_t *rcvd_msg)
{
    chilog(TRACE, "handling PING");
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, rcvd_msg);
        return 1;
    }
    message_t *msg = calloc(1, sizeof(message_t));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    msg_construct(msg, server->server_hostname, "PONG");
    msg_add_param(msg, server->server_hostname, true);
    msg_to_string(msg, &reply);
    send_string_to_user(user, reply);
    chilog(INFO, "PONG response successfully sent: %s", reply);

    free(reply);
    msg_destroy(msg);
    return 0;
}

int user_handle_PONG(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "handling PONG");
    chilog(DEBUG, "user_handle_PONG: silently ignored");
    return 0;
}

int user_handle_WHOIS(server_t *server, user_t *user, message_t *msg)
{
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }

    if (msg->nparams == 0)
    {
        chilog(DEBUG, "user_handle_WHOIS: no parameter, silently ignore");
        return 0;
    }

    char *nickname = msg->params[0];
    user_t *target_user = find_user(server->all_users, nickname);
    if (target_user == NULL)
    {
        send_response(ERR_NOSUCHNICK, server, user, msg);
        return 1;
    }

    send_response(RPL_WHOISUSER, server, user, msg);
    /* to be fixed */
    if (user->user_channels != NULL)
    {
        send_response(RPL_WHOISCHANNELS, server, user, msg);
    }
    send_response(RPL_WHOISSERVER, server, user, msg);
    if (target_user->is_irc_op)
    {
        send_response(RPL_WHOISOPERATOR, server, user, msg);
    }
    send_response(RPL_ENDOFWHOIS, server, user, msg);
}

int user_handle_OPER(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "handling OPER");
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }
    if (msg->nparams < 2)
    {
        send_response(ERR_NEEDMOREPARAMS, server, user, msg);
        return 1;
    }
    /* check if password is correct */
    if (strcmp(server->passwd, msg->params[1]) == 0)
    {
        pthread_mutex_lock(&server->user_lock);
        server->num_operator++;
        pthread_mutex_unlock(&server->user_lock);

        pthread_mutex_lock(&user->user_lock_individual);
        user->is_irc_op = true;
        pthread_mutex_unlock(&user->user_lock_individual);

        send_response(RPL_YOUREOPER, server, user, msg);
        return 0;
    }
    else
    {
        send_response(ERR_PASSWDMISMATCH, server, user, msg);
        return 1;
    }
}

int user_handle_JOIN(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "handling JOIN");
    relay_command_to_servers(server, user, msg);
    if (!user->is_registered)
    {
        chilog(DEBUG, "unregistered user");
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }
    if (msg->nparams < 1)
    {
        chilog(DEBUG, "need more params");
        send_response(ERR_NEEDMOREPARAMS, server, user, msg);
        return 1;
    }
    char *channel_name = msg->params[0];
    channel_t *channel = find_channel(server->all_channels, channel_name);

    /* silent ignore if user is already in channel */
    if (channel != NULL && is_user_in_channel(channel, user))
    {
        chilog(DEBUG, "user already in channel, silently ignore");
        return 0;
    }
    if (channel == NULL)
    {
        channel = create_channel(channel_name);
        add_channel_to_server(server, channel);
        add_user_to_channel(channel, user);
        send_cmd_to_channel(server, user, channel, msg);
        /* first user joined is automatically operator */
        add_user_to_channel_ops(channel, user);
        send_response(RPL_NAMREPLY, server, user, msg);
        send_response(RPL_ENDOFNAMES, server, user, msg);
        return 0;
    }
    add_user_to_channel(channel, user);
    send_cmd_to_channel(server, user, channel, msg);
    send_response(RPL_NAMREPLY, server, user, msg);
    send_response(RPL_ENDOFNAMES, server, user, msg);
    return 0;
}

int user_handle_PRIVMSG(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "handling PRIVMSG");
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }
    if (msg->nparams == 0)
    {
        send_response(ERR_NORECIPIENT, server, user, msg);
        return 1;
    }
    if (msg->nparams == 1)
    {
        if (msg->longlast)
        {
            send_response(ERR_NORECIPIENT, server, user, msg);
            return 1;
        }
        else
        {
            send_response(ERR_NOTEXTTOSEND, server, user, msg);
            return 1;
        }
    }
    user_t *target_user = find_user(server->all_users, msg->params[0]);

    if (target_user == NULL)
    {
        channel_t *target_channel = find_channel(server->all_channels, msg->params[0]);
        /* check if the target is a channel */
        if (target_channel == NULL)
        {
            chilog(DEBUG, "No such channel");
            send_response(ERR_NOSUCHNICK, server, user, msg);
            return 1;
        }
        else
        {
            /* if the target is channel, relay to all servers */
            relay_command_to_servers(server, user, msg);
            /* check if user is in this channel */
            if (is_user_in_channel(target_channel, user))
            {
                send_cmd_to_channel(server, user, target_channel, msg);
            }
            else
            {
                send_response(ERR_CANNOTSENDTOCHAN, server, user, msg);
            }
            return 0;
        }
    }
    else
    {
        /* the target is then a user */
        /* if the target user is not in the same server, relay to all servers */
        if (target_user->connection_to_server == NULL)
        {
            relay_command_to_servers(server, user, msg);
        }
        else
        {
            send_privmsg_to_user(server, user, target_user, msg);
        }
        return 0;
    }
}

int user_handle_NOTICE(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "handling NOTICE");
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }
    /* NOTICE doesn't reply ERROR message */
    if (msg->nparams < 2)
    {
        chilog(DEBUG, "no parameter, silently ignore");
        return 1;
    }
    user_t *target_user = find_user(server->all_users, msg->params[0]);

    if (target_user == NULL)
    {
        /* check if the target is a chennel */
        channel_t *target_channel = find_channel(server->all_channels, msg->params[0]);
        if (target_channel == NULL)
        {
            return 1;
        }
        else
        {
            send_cmd_to_channel(server, user, target_channel, msg);
            return 0;
        }
    }
    else
    {
        send_privmsg_to_user(server, user, target_user, msg);
        return 0;
    }
}

int user_handle_MODE(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "handling MODE");
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }
    /* MODE can be run without parameter */
    if (msg->nparams < 3)
    {
        return 0;
    }
    channel_t *channel = find_channel(server->all_channels, msg->params[0]);

    /* check if the channel exists*/
    if (channel == NULL)
    {
        send_response(ERR_NOSUCHCHANNEL, server, user, msg);
        return 1;
    }

    /* check if user has channel privilege */
    if (!user->is_irc_op && !is_user_channel_op(channel, user))
    {
        send_response(ERR_CHANOPRIVSNEEDED, server, user, msg);
        return 1;
    }
    user_t *target_user = find_user(server->all_users, msg->params[2]);
    if (target_user == NULL || !is_user_in_channel(channel, user))
    {
        send_response(ERR_USERNOTINCHANNEL, server, user, msg);
        return 1;
    }
    if (!strcmp(msg->params[1], "-o"))
    {
        /* remove user's operator privilege */
        rm_user_from_channel_ops(channel, target_user);
        send_cmd_to_channel(server, user, channel, msg);
        return 0;
    }
    else if (!strcmp(msg->params[1], "+o"))
    {
        /* grant user operator privilege */
        add_user_to_channel_ops(channel, target_user);
        send_cmd_to_channel(server, user, channel, msg);
        return 0;
    }
    else
    {
        /* other modes are not supported yet */
        send_response(ERR_UNKNOWNMODE, server, user, msg);
        return 1;
    }
    return 0;
}

int user_handle_PART(server_t *server, user_t *user, message_t *msg)
{
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }
    if (msg->nparams == 0)
    {
        send_response(ERR_NEEDMOREPARAMS, server, user, msg);
        return 1;
    }
    channel_t *channel = find_channel(server->all_channels, msg->params[0]);
    /* check if target channel exists */
    if (channel == NULL)
    {
        send_response(ERR_NOSUCHCHANNEL, server, user, msg);
        return 1;
    }
    /* check if the sender is in channel */
    if (!is_user_in_channel(channel, user))
    {
        send_response(ERR_NOTONCHANNEL, server, user, msg);
        return 1;
    }
    /* send PART message to everyone in the channel */
    send_cmd_to_channel(server, user, channel, msg);
    delete_user_from_channel(channel, user);

    /* destroy the channel if there's no one in it */
    if (num_users_in_channel(channel) == 0)
    {
        delete_channel_from_server(server, channel);
    }
    return 0;
}

int user_handle_LIST(server_t *server, user_t *user, message_t *msg)
{
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }
    /* when there is no parameter, list information of all channels */
    if (msg->nparams == 0)
    {
        channel_t *curr, *tmp;
        HASH_ITER(hh, server->all_channels, curr, tmp)
        {
            send_channel_info(curr, user);
        }
        send_response(RPL_LISTEND, server, user, msg);
        return 0;
    }
    else
    {
        send_response(RPL_LIST, server, user, msg);
        send_response(RPL_LISTEND, server, user, msg);
        return 0;
    }
}

int user_handle_CONNECT(server_t *server, user_t *user, message_t *msg)
{
    if (!user->is_registered)
    {
        send_response(ERR_NOTREGISTERED, server, user, msg);
        return 1;
    }
    /* check if the user has IRC operator privilege */
    if (!user->is_irc_op)
    {
        send_response(ERR_NOPRIVILEGES, server, user, msg);
        return 1;
    }
    if (msg->nparams < 2)
    {
        send_response(ERR_NEEDMOREPARAMS, server, user, msg);
        return 1;
    }
    char *server_name = msg->params[0];
    network_spec_t *network_spec = find_network_spec(server, server_name);
    remote_server_t *target_server = find_remote_server(server->all_remote_servers, server_name);
    if (network_spec == NULL)
    {
        send_response(ERR_NOSUCHSERVER, server, user, msg);
        return 1;
    }
    chilog(TRACE, "trying to connect to remote server: \"%s\"", server_name);
    connect_remote_server(server, server_name);
    return 0;
}

int server_handle_NICK(server_t *server, remote_server_t *remote_server, message_t *msg)
{
    chilog(TRACE, "server handling nick");
    user_t *user = create_user(NULL);
    strcpy(user->nickname, msg->params[0]);
    strcpy(user->username, msg->params[2]);
    strcpy(user->hostname, msg->params[3]);
    strcpy(user->realname, msg->params[6]);
    strcpy(user->connected_server_name, remote_server->servername);
    add_user_to_server(server, user);

    if (find_user(server->all_users, user->nickname) == NULL)
    {
        chilog(ERROR, "adding to hashtable failed");
        return 1;
    }
    chilog(DEBUG, "user \"%s\" from \"%s\" added to server",
        user->nickname, remote_server->servername);
    chilog(DEBUG, "there are %d users in total", num_users(server->all_users));
    return 0;
}

int server_handle_SERVER(server_t *server, remote_server_t *remote_server, message_t *msg)
{
    /* ignore error if the remote server is the passive server */
    if (remote_server->is_registered && !remote_server->is_passive)
    {
        send_response_server(ERR_ALREADYREGISTRED, server, remote_server, msg);
        return 1;
    }
    strcpy(remote_server->servername, msg->params[0]);
    if (strcmp(remote_server->rcvd_password, "") != 0)
    {
        register_server(server, remote_server);
    }
    return 0;
}

int server_handle_PASS(server_t *server, remote_server_t *remote_server, message_t *msg)
{
    /* ignore error if the remote server is the passive server */
    if (remote_server->is_registered && !remote_server->is_passive)
    {
        send_response_server(ERR_ALREADYREGISTRED, server, remote_server, msg);
        return 1;
    }
    strcpy(remote_server->rcvd_password, msg->params[0]);
    if (strcmp(remote_server->servername, "") != 0)
    {
        register_server(server, remote_server);
    }
    return 0;
}

int server_handle_PRIVMSG(server_t *server, remote_server_t *remote_server, message_t *msg)
{
    user_t *target_user = find_user(server->all_users, msg->params[0]);
    user_t *sender = find_user(server->all_users, msg->prefix + 1);
    if (sender == NULL)
    {
        chilog(ERROR, "sender is not in hashtable");
    }

    if (target_user == NULL)
    {
        channel_t *target_channel = find_channel(server->all_channels, msg->params[0]);
        send_cmd_to_channel(server, sender, target_channel, msg);
    }
    else
    {
        /* the target is then a user */
        /* if the target user is not in the same server, relay to all servers */
        if (target_user->connection_to_server == NULL)
        {
            return 0;
        }
        else
        {
            send_privmsg_to_user(server, sender, target_user, msg);
        }
        return 0;
    }
    return 0;
}

int server_handle_JOIN(server_t *server, remote_server_t *remote_server, message_t *msg)
{
    char *channel_name = msg->params[0];
    channel_t *channel = find_channel(server->all_channels, channel_name);
    user_t *user = find_user(server->all_users, msg->prefix + 1);

    /* silent ignore if user is already in channel */
    if (channel != NULL && is_user_in_channel(channel, user))
    {
        chilog(DEBUG, "user already in channel, silently ignore");
        return 0;
    }
    if (channel == NULL)
    {
        channel = create_channel(channel_name);
        add_channel_to_server(server, channel);
        add_user_to_channel(channel, user);
        send_cmd_to_channel(server, user, channel, msg);
        /* first user joined is automatically operator */
        add_user_to_channel_ops(channel, user);
        return 0;
    }
    add_user_to_channel(channel, user);
    send_cmd_to_channel(server, user, channel, msg);
    return 0;
}

int register_user(server_t *server, user_t *user, message_t *msg)
{
    chilog(TRACE, "register_user");
    if (user->nickname != NULL && user->username != NULL)
    {
        chilog(TRACE, "register_user: nickname: \"%s\"", user->nickname);
        chilog(TRACE, "register_user: username: \"%s\"", user->username);
        add_user_to_server(server, user);

        user->is_registered = true;
        chilog(INFO, "user \"%s\" registered", user->nickname);
        chilog(DEBUG, "there are %d users in total", num_users(server->all_users));
        send_response(RPL_WELCOME, server, user, msg);
        send_response(RPL_YOURHOST, server, user, msg);
        send_response(RPL_CREATED, server, user, msg);
        send_response(RPL_MYINFO, server, user, msg);
        send_response(RPL_LUSERCLIENT, server, user, msg);
        send_response(RPL_LUSEROP, server, user, msg);
        send_response(RPL_LUSERUNKNOWN, server, user, msg);
        send_response(RPL_LUSERCHANNELS, server, user, msg);
        send_response(RPL_LUSERME, server, user, msg);
        send_response(ERR_NOMOTD, server, user, msg);

        /* notify other servers of new users joining the IRC network */
        send_nick_to_servers(server, user);
        return 0;
    }
    else
    {
        chilog(DEBUG, "missing username or nickname");
        return 1;
    }
}

int register_server(server_t *server, remote_server_t *remote_server)
{
    message_t *err_msg = calloc(1, sizeof(message_t));
    char *long_param = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    network_spec_t *network_spec = find_network_spec(server, remote_server->servername);
    remote_server_t *existing_remote = find_remote_server
    (server->all_remote_servers, remote_server->servername);

    msg_construct(err_msg, server->server_hostname, "ERROR");

    chilog(TRACE, "server password: %s", server->passwd);
    chilog(TRACE, "received password: %s", remote_server->rcvd_password);
    /* in this case, the server is not part of the network */
    if (network_spec == NULL)
    {
        sprintf(long_param, "Server not configured here");
        msg_add_param(err_msg, long_param, true);
        msg_to_string(err_msg, &reply);
        send_string_to_remote_server(remote_server, reply);
        return 1;
    }
    /* in this case, password doesn't match */
    else if (strcmp(server->connection_passwd, remote_server->rcvd_password) != 0)
    {
        sprintf(long_param, "Bad password");
        msg_add_param(err_msg, long_param, true);
        msg_to_string(err_msg, &reply);
        send_string_to_remote_server(remote_server, reply);
        return 1;
    }
    /* in this case, the server is already registered */
    else if (existing_remote != NULL)
    {
        sprintf(long_param, "ID \"%s\" already registered", remote_server->servername);
        msg_add_param(err_msg, long_param, true);
        msg_to_string(err_msg, &reply);
        send_string_to_remote_server(remote_server, reply);
        return 1;
    }

    msg_destroy(err_msg);
    free(long_param);
    free(reply);

    add_remote_server_to_server(server, remote_server);
    remote_server->is_registered = true;

    /* do not send PASS SERVER again if the remote server is passive
     * (which means the server we are on has already sent PASS SERVER) */
    if (remote_server->is_passive) 
    {
        return 0;
    }

    message_t *pass_msg = calloc(1, sizeof(message_t));
    message_t *server_msg = calloc(1, sizeof(message_t));
    char *pass_reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *server_reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));

    msg_construct(pass_msg, server->server_name, "PASS");
    msg_add_param(pass_msg, network_spec->passwd, false);
    msg_add_param(pass_msg, "0210", false);
    msg_add_param(pass_msg, server->version, false);
    msg_to_string(pass_msg, &pass_reply);
    send_string_to_remote_server(remote_server, pass_reply);

    msg_construct(server_msg, server->server_name, "SERVER");
    msg_add_param(server_msg, server->server_name, false);
    msg_add_param(server_msg, "1", false);
    msg_add_param(server_msg, "hello there", true);
    msg_to_string(server_msg, &server_reply);
    send_string_to_remote_server(remote_server, server_reply);

    msg_destroy(pass_msg);
    msg_destroy(server_msg);
    free(pass_reply);
    free(server_reply);
    return 0;
}

int change_user_nick(server_t *server, user_t *user, message_t *rcvd_msg)
{
    message_t *msg = calloc(1, sizeof(message_t));
    message_t *channel_msg = calloc(1, sizeof(message_t));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *prefix = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *channel_reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    msg_construct(msg, user->nickname, "NICK");
    msg_add_param(msg, rcvd_msg->params[0], true);
    msg_to_string(msg, &reply);
    chilog(INFO, "response successfully sent: %s", reply);
    /* send PART message to user */
    send_string_to_user(user, reply);

    /* send PART message to all the channels user is in */
    sprintf(prefix, "%s!%s@%s", user->nickname, user->username, server->server_hostname);
    msg_construct(channel_msg, user->nickname, "NICK");
    msg_add_param(channel_msg, rcvd_msg->params[0], true);
    msg_to_string(channel_msg, &channel_reply);
    send_string_to_user_channels(user, channel_reply);

    free(reply);
    free(channel_reply);
    free(prefix);
    msg_destroy(msg);
    msg_destroy(channel_msg);
    return 0;
}

int send_privmsg_to_user(server_t *server, user_t *user, user_t *target_user, message_t *rcvd_msg)
{
    message_t *msg = calloc(1, sizeof(message_t));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *prefix = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    chilog(TRACE, "nickname: \"%s\"", user->nickname);
    chilog(TRACE, "username: \"%s\"", user->username);
    chilog(TRACE, "hostname: \"%s\"", user->hostname);
    sprintf(prefix, "%s!%s@%s", user->nickname, user->username, server->server_hostname);
    msg_construct(msg, prefix, rcvd_msg->cmd);
    msg_add_param(msg, rcvd_msg->params[0], false);
    msg_add_param(msg, rcvd_msg->params[1], true);
    msg_to_string(msg, &reply);
    send_string_to_user(target_user, reply);
    chilog(INFO, "response successfully sent: %s", reply);

    free(reply);
    free(prefix);
    msg_destroy(msg);
    return 0;
}

int send_cmd_to_channel(server_t *server, user_t *user, channel_t *target_channel, message_t *rcvd_msg)
{
    message_t *msg = calloc(1, sizeof(message_t));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *prefix = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    sprintf(prefix, "%s!%s@%s", user->nickname, user->username, server->server_hostname);
    msg_construct(msg, prefix, rcvd_msg->cmd);
    for (int i = 0; i < rcvd_msg->nparams - 1; i++)
    {
        msg_add_param(msg, rcvd_msg->params[i], false);
    }
    msg_add_param(msg, rcvd_msg->params[rcvd_msg->nparams - 1], rcvd_msg->longlast);
    msg_to_string(msg, &reply);
    chilog(TRACE, "string ready to sent: %s", reply);
    if (strcmp(rcvd_msg->cmd, "PRIVMSG") == 0 || strcmp(rcvd_msg->cmd, "NOTICE") == 0)
    {
        /* skip the sender if the command is PRIVMSG or NOTICE */
        send_string_to_channel(target_channel, reply, user);
    }
    else
    {
        send_string_to_channel(target_channel, reply, NULL);
    }
    chilog(INFO, "response successfully sent to channel: %s", reply);

    free(reply);
    free(prefix);
    msg_destroy(msg);
    return 0;
}

int send_channel_info(channel_t *channel, user_t *user)
{
    message_t *msg = calloc(1, sizeof(user_t));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *buf = calloc(MAX_COUNT_NUM_DIGIT, sizeof(char));
    msg_construct(msg, user->nickname, "322");
    msg_add_param(msg, user->nickname, false);
    msg_add_param(msg, channel->channel_name, false);
    sprintf(buf, "%d", num_users_in_channel(channel));
    msg_add_param(msg, buf, false);
    msg_add_param(msg, "topic", true);
    msg_to_string(msg, &reply);
    send_string_to_user(user, reply);
    chilog(INFO, "response successfully sent: %s", reply);

    free(reply);
    free(buf);
    msg_destroy(msg);
    return 0;
}

int send_quit_message(server_t *server, user_t *user, message_t *rcvd_msg)
{
    message_t *msg = calloc(1, sizeof(message_t));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *prefix = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    sprintf(prefix, "%s!%s@%s", user->nickname, user->username, server->server_hostname);
    msg_construct(msg, prefix, "QUIT");

    if (rcvd_msg->longlast)
    {
        msg_add_param(msg, rcvd_msg->params[0], true);
    }
    else
    {
        msg_add_param(msg, "Client Quit", true);
    }

    msg_to_string(msg, &reply);
    send_string_to_user_channels(user, reply);
    chilog(INFO, "response successfully sent: %s", reply);

    free(reply);
    free(prefix);
    msg_destroy(msg);
}

int send_nick_to_servers(server_t *server, user_t *user)
{
    message_t *msg = calloc(1, sizeof(message_t));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    msg_construct(msg, server->server_name, "NICK");
    msg_add_param(msg, user->nickname, false);
    msg_add_param(msg, "1", false);
    msg_add_param(msg, user->username, false);
    msg_add_param(msg, user->hostname, false);
    msg_add_param(msg, "1", false);
    msg_add_param(msg, "+", false);
    msg_add_param(msg, user->realname, true);
    msg_to_string(msg, &reply);
    send_string_to_all_remote_servers(server, reply);

    msg_destroy(msg);
    free(reply);
    return 0;
}

int relay_command_to_servers(server_t *server, user_t *user, message_t *rcvd_msg)
{
    message_t *msg = calloc(1, sizeof(message_t));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    msg_construct(msg, user->nickname, rcvd_msg->cmd);
    for (int i = 0; i < rcvd_msg->nparams - 1; i++)
    {
        msg_add_param(msg, rcvd_msg->params[i], false);
    }
    msg_add_param(msg, rcvd_msg->params[rcvd_msg->nparams - 1], rcvd_msg->longlast);
    msg_to_string(msg, &reply);
    send_string_to_all_remote_servers(server, reply);

    msg_destroy(msg);
    free(reply);
    return 0;
}