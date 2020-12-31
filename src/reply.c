#include "reply.h"
#include "message.h"
#include "user.h"
#include "channel.h"

int send_response(char* numeric, server_t *server, user_t *user, message_t *rcvd_msg)
{
    message_t *msg = calloc(1, sizeof(message_t));
    char *long_param = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));

    msg_construct(msg, server->server_hostname, numeric);
    if (strcmp(user->nickname, "") != 0)
    {
        msg_add_param(msg, user->nickname, false);
    }
    else
    {
        /* if user has no nickname yet, use * instead */
        msg_add_param(msg, "*", false);
    }

    /* using the numeric as the indicator of the switch statement */
    switch (atoi(numeric))
    {
        /* RPL_WELCOME */
        case 1:
            sprintf(long_param, "Welcome to the Internet Relay Network %s!%s@%s",
                user->nickname, user->username, user->hostname);
            msg_add_param(msg, long_param, true);
            break;
        /* RPL_YOURHOST */
        case 2:
            sprintf(long_param, "Your host is %s, running version %s",
                server->server_hostname, server->version);
            msg_add_param(msg, long_param, true);
            break;
        /* RPL_CREATED */
        case 3:
            sprintf(long_param, "This server was created %s", server->time_created);
            msg_add_param(msg, long_param, true);
            break;
        /* RPL_MYINFO */
        case 4:
            msg_add_param(msg, server->server_name, false);
            msg_add_param(msg, server->version, false);
            msg_add_param(msg, "ao", false);
            msg_add_param(msg, "mtov", false);
            break;
        /* RPL_LUSERCLIENT */
        case 251:
            /* to be modified when there are more servers */
            chilog(DEBUG, "is user NULL: %d", !server->all_users);
            sprintf(long_param, "There are %d users and %d services on %d servers",
                num_users(server->all_users), 0, 1 + num_remote_servers(server->all_remote_servers));
            msg_add_param(msg, long_param, true);
            break;
        /* RPL_LUSEROP */
        case 252:
        {
            char *buf = calloc(MAX_COUNT_NUM_DIGIT, sizeof(char));
            sprintf(buf, "%d", server->num_operator);
            msg_add_param(msg, buf, false);
            sprintf(long_param, "operator(s) online");
            msg_add_param(msg, long_param, true);
            free(buf);
            break;
        }
        /* RPL_LUSERUNKNOWN */
        case 253:
        {
            char *buf = calloc(MAX_COUNT_NUM_DIGIT, sizeof(char));
            int num_unknown_conn = server->num_total_connection
                - server->num_user_connection - server->num_server_connection;
            sprintf(buf, "%d", num_unknown_conn);
            msg_add_param(msg, buf, false);
            sprintf(long_param, "unknown connection(s)");
            msg_add_param(msg, long_param, true);
            free(buf);
            break;
        }
        /* RPL_LUSERCHANNELS */
        case 254:
        {
            char *buf = calloc(MAX_COUNT_NUM_DIGIT, sizeof(char));
            int num_channel = num_channels(server->all_channels);
            sprintf(buf, "%d", num_channel);
            msg_add_param(msg, buf, false);
            sprintf(long_param, "channels formed");
            msg_add_param(msg, long_param, true);
            free(buf);
            break;
        }
        /* RPL_LUSERME */
        case 255:
            sprintf(long_param, "I have %d clients and %d servers",
                server->num_user_connection, server->num_server_connection);
            msg_add_param(msg, long_param, true);
            break;
        /* RPL_WHOISUSER */
        case 311:
        {
            user_t *target = find_user(server->all_users, rcvd_msg->params[0]);
            msg_add_param(msg, target->nickname, false);
            msg_add_param(msg, target->username, false);
            msg_add_param(msg, target->hostname, false);
            msg_add_param(msg, "*", false);
            strcpy(long_param, target->realname);
            msg_add_param(msg, long_param, true);
            break;
        }
        /* RPL_WHOISSERVER */
        case 312:
        {
            user_t *target = find_user(server->all_users, rcvd_msg->params[0]);
            msg_add_param(msg, rcvd_msg->params[0], false);
            msg_add_param(msg, target->connected_server_name, false);
            sprintf(long_param, "server info");
            msg_add_param(msg, long_param, true);
            break;
        }
        /* RPL_WHOISOPERATOR*/
        case 313:
            msg_add_param(msg, msg->params[0], false);
            sprintf(long_param, "is an IRC operator");
            msg_add_param(msg, long_param, true);
            break;
        /* RPL_ENDOFWHOIS */
        case 318:
            msg_add_param(msg, msg->params[0], false);
            sprintf(long_param, "End of WHOIS list");
            msg_add_param(msg, long_param, true);
            break;
        /* RPL_WHOISCHANNELS */
        case 319:
        {
            user_t *target = find_user(server->all_users, msg->params[0]);
            msg_add_param(msg, msg->params[0], false);
            long_param = list_user_channels(target);
            msg_add_param(msg, long_param, true);
            break;
        }
        /* RPL_LIST */
        case 322:
        {
            channel_t *channel = find_channel(server->all_channels, msg->params[0]);
            char *buf = calloc(MAX_COUNT_NUM_DIGIT, sizeof(char));
            msg_add_param(msg, msg->params[0], false);
            sprintf(buf, "%d", num_users_in_channel(channel));
            msg_add_param(msg, buf, false);
            sprintf(long_param, "topic");
            msg_add_param(msg, long_param, true);
            free(buf);
            break;
        }
        /* RPL_LISTEND */
        case 323:
            sprintf(long_param, "End of LIST");
            msg_add_param(msg, long_param, true);
            break;
        /* RPL_NAMREPLY */
        case 353:
        {
            char *name = rcvd_msg->params[0];
            channel_t *channel = find_channel(server->all_channels, name);
            msg_add_param(msg, "=", false);
            msg_add_param(msg, name, false);
            long_param = list_users_in_channel(channel);
            msg_add_param(msg, long_param, true);
            break;
        }
        /* RPL_ENDOFNAMES */
        case 366:
        {
            char *name = rcvd_msg->params[0];
            msg_add_param(msg, name, false);
            sprintf(long_param, "End of NAMES list");
            msg_add_param(msg, long_param, true);
            break;
        }
        /* RPL_YOUREOPER */
        case 381:
            sprintf(long_param, "You are now an IRC operator");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NOSUCHNICK */
        case 401:
            msg_add_param(msg, rcvd_msg->params[0], false);
            sprintf(long_param, "No such nick/channel");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NOSUCHSERVER */
        case 402:
            msg_add_param(msg, rcvd_msg->params[0], false);
            sprintf(long_param, "No such server");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NOSUCHCHANNEL */
        case 403:
            msg_add_param(msg, rcvd_msg->params[0], false);
            sprintf(long_param, "No such channel");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_CANNOTSENDTOCHAN */
        case 404:
            msg_add_param(msg, rcvd_msg->params[0], false);
            sprintf(long_param, "Cannot send to channel");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NORECIPIENT */
        case 411:
            sprintf(long_param, "No recipient given (%s)", rcvd_msg->cmd);
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NOTEXTTOSEND */
        case 412:
            sprintf(long_param, "No text to send");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_UNKNOWNCOMMAND */
        case 421:
            msg_add_param(msg, rcvd_msg->cmd, false);
            sprintf(long_param, "Unknown command");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NOMOTD */
        case 422:
            sprintf(long_param, "MOTD File is missing");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NONICKNAMEGIVEN */
        case 431:
            sprintf(long_param, "No nickname given");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NICKNAMEINUSE */
        case 433:
            msg_add_param(msg, rcvd_msg->params[0], false);
            sprintf(long_param, "Nickname is already in use");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_USERNOTINCHANNEL */
        case 441:
            msg_add_param(msg, rcvd_msg->params[2], false);
            msg_add_param(msg, rcvd_msg->params[0], false);
            sprintf(long_param, "They aren't on that channel");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NOTONCHANNEL */
        case 442:
            msg_add_param(msg, rcvd_msg->params[0], false);
            sprintf(long_param, "You're not on that channel");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NOTREGISTERED */
        case 451:
            sprintf(long_param, "You have not registered");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NEEDMOREPARAMS */
        case 461:
            msg_add_param(msg, rcvd_msg->cmd, false);
            sprintf(long_param, "Not enough parameters");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_PASSWDMISMATCH */
        case 464:
            sprintf(long_param, "Password incorrect");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_UNKNOWNMODE */
        case 472:
            msg_add_param(msg, rcvd_msg->params[1], false);
            sprintf(long_param, "is unknown mode char to me for %s", rcvd_msg->params[0]);
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_NOPRIVILEGES */
        case 481:
            sprintf(long_param, "Permission Denied- You're not an IRC operator");
            msg_add_param(msg, long_param, true);
            break;
        /* ERR_CHANOPRIVSNEEDED */
        case 482:
            msg_add_param(msg, rcvd_msg->params[0], false);
            sprintf(long_param, "You're not channel operator");
            msg_add_param(msg, long_param, true);
            break;
        default:
            chilog(DEBUG, "Unknown numeric code %i\n", atoi(numeric));
            return 2;
            break;
    }

    msg_to_string(msg, &reply);
    send_string_to_user(user, reply);
    chilog(INFO, "response successfully sent: %s", reply);

    free(long_param);
    free(reply);
    msg_destroy(msg);
    return 0;
}

int send_response_server(char* numeric, server_t *server, remote_server_t *remote_server, message_t *rcvd_msg)
{
    message_t *msg = calloc(1, sizeof(message_t));
    char *long_param = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));

    msg_construct(msg, server->server_name, numeric);
    msg_add_param(msg, remote_server->servername, false);
    switch (atoi(numeric))
    {
        /* ERR_ALREADYREGISTRED */
        case 462:
            sprintf(long_param, "Connection already registered");
            msg_add_param(msg, long_param, true);
            break;
    }
    msg_to_string(msg, &reply);
    send_string_to_remote_server(remote_server, reply);
    chilog(INFO, "response successfully sent: %s", reply);

    free(long_param);
    free(reply);
    msg_destroy(msg);
    return 0;
}
