#include "user.h"
#include "log.h"
#include "reply.h"

user_t *create_user(connection_t *connection)
{
    user_t *user = calloc(1, sizeof(user_t));
    user->connection_to_server = connection;
    pthread_mutex_init(&user->user_lock_individual, NULL);
    return user;
}

int add_user_to_server(server_t *server, user_t *user)
{
    chilog(TRACE, "add_user_to_server");
    pthread_mutex_lock(&server->user_lock);
    HASH_ADD_STR(server->all_users, nickname, user);
    pthread_mutex_unlock(&server->user_lock);
    chilog(DEBUG, "user \"%s\" added to server hashtable", user->nickname);
    return 0;
}

int num_users(user_t *all_users)
{
    return HASH_COUNT(all_users);
}

user_t *find_user(user_t *all_users, char *nickname)
{
    user_t *user;
    /* this function returns NULL if user is not found */
    HASH_FIND_STR(all_users, nickname, user);
    return user;
}

int delete_user(user_t **all_users, user_t *user)
{
    HASH_DEL(*all_users, user);
    chilog(DEBUG, "user \"%s\" deleted from hashtable", user->nickname);
    channel_hash_t *curr_channel_wrapped, *tmp;
    HASH_ITER(hh, user->user_channels, curr_channel_wrapped, tmp)
    {
        delete_user_from_channel(curr_channel_wrapped->channel, user);
    }

    /* Don't free user yet! Still gonna be used in send_quit_message */
    /* free(user); */
}

int send_string_to_user(user_t *user, char* str)
{
    connection_t *connection = user->connection_to_server;
    int socket = connection->socket;
    /* using lock to protect send */
    pthread_mutex_lock(&connection->connection_socket_lock);
    if (!send_all(socket, str, strlen(str), 0))
    {
        chilog(ERROR, "socket send() failed");
        pthread_mutex_unlock(&connection->connection_socket_lock);
        return 1;
    }
    pthread_mutex_unlock(&connection->connection_socket_lock);
    chilog(INFO, "string ||| %s ||| sent to user %s", str, user->nickname);
    return 0;
}
