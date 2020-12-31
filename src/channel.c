#include "channel.h"

channel_t *create_channel(char *channel_name)
{
    channel_t *channel = calloc(1, sizeof(channel_t));
    strcpy(channel->channel_name, channel_name);
    pthread_mutex_init(&channel->channel_lock_individual, NULL);
    chilog(DEBUG, "channel created: %s", channel_name);
    return channel;
}

int add_channel_to_server(server_t *server, channel_t *channel)
{
    pthread_mutex_lock(&server->channel_lock);
    HASH_ADD_STR(server->all_channels, channel_name, channel);
    pthread_mutex_unlock(&server->channel_lock);
    chilog(DEBUG, "channel \"%s\" added to server hashtable", channel->channel_name);
    return 0;
}

int add_user_to_channel(channel_t *channel, user_t *user)
{
    /* === update the user list of a channel === */

    /* wrap user_t to a user_hash_t */
    user_hash_t *user_wrapped = calloc(1, sizeof(user_hash_t));
    user_wrapped->user = user;
    strncpy(user_wrapped->name, user->nickname, NICK_STR_SZ);

    pthread_mutex_lock(&channel->channel_lock_individual);
    HASH_ADD_STR(channel->channel_users, name, user_wrapped);
    pthread_mutex_unlock(&channel->channel_lock_individual);
    chilog(DEBUG, "user %s added to channel", user->nickname);

    /* ========================================= */

    /* === update the channel list of a user === */

    /* wrap channel_t to a channel_hash_t */
    channel_hash_t *channel_wrapped = calloc(1, sizeof(channel_hash_t));
    channel_wrapped->channel = channel;
    strncpy(channel_wrapped->name, channel->channel_name, MAX_CHANNEL_STR_SZ);

    pthread_mutex_lock(&user->user_lock_individual);
    HASH_ADD_STR(user->user_channels, name, channel_wrapped);
    pthread_mutex_unlock(&user->user_lock_individual);
    chilog(DEBUG, "channel %s added to user", channel->channel_name);

    /* ========================================= */

    return 0;
}

int num_channels(channel_t *all_channels)
{
    return HASH_COUNT(all_channels);
}

channel_t *find_channel(channel_t *all_channels, char *channel_name)
{
    channel_t *channel;
    HASH_FIND_STR(all_channels, channel_name, channel);
    return channel;
}

int delete_channel_from_server(server_t *server, channel_t *channel)
{
    user_hash_t *curr, *tmp;

    /* detect whether the deletion is success */
    int prev_num_channels = num_channels(server->all_channels);

    /* delete from the server */
    pthread_mutex_lock(&server->channel_lock);
    HASH_DEL(server->all_channels, channel);
    pthread_mutex_unlock(&server->channel_lock);
    chilog(DEBUG, "channel \"%s\" deleted from hashtable", channel->channel_name);

    /* delete the channel from all the users who were in this channel */
    HASH_ITER(hh, channel->channel_users, curr, tmp)
    {
        user_t *user = curr->user;
        /* this function is thread safe */
        delete_user_from_channel(channel, user);
    }

    free(channel);

    if (num_channels(server->all_channels) == prev_num_channels - 1)
    {
        return 0;
    }
    else
    {
        chilog(ERROR, "deletion failed, no decrement in num_channels");
        return 1;
    }

}

char *list_users_in_channel(channel_t *channel)
{
    chilog(TRACE, "listing users in channel %s", channel->channel_name);
    char *res = calloc(NICK_STR_SZ * MAX_USER_NUM, sizeof(char));
    user_hash_t *curr_user_wrapped, *tmp;
    HASH_ITER(hh, channel->channel_users, curr_user_wrapped, tmp)
    {
        /* add space separator if it's not the first */
        if (strlen(res)) strcat(res, " ");

        strcat(res, curr_user_wrapped->user->nickname);
        chilog(TRACE, "res status: %s", res);
    }
    chilog(TRACE, "ending list users in channel");
    return res;
}

int send_string_to_channel(channel_t *channel, char* str, user_t *skipped_user)
{
    bool flag_all_sent = true;
    user_hash_t *curr_user_wrapped, *tmp;
    HASH_ITER(hh, channel->channel_users, curr_user_wrapped, tmp)
    {
        /* skip the sender themselves; safe even if NULL */
        /* skip the users who are in remote servers */
        if (curr_user_wrapped->user == skipped_user ||
            curr_user_wrapped->user->connection_to_server == NULL)
        {
            continue;
        }
        /* send_string_to_user is thread safe */
        if (send_string_to_user(curr_user_wrapped->user, str) != 0)
        {
            flag_all_sent = false;
        }
    }
    if (!flag_all_sent)
    {
        chilog(ERROR, "channel send failed on some connections");
        return 1;
    }
    return 0;
}

char *list_user_channels(user_t *user)
{
    char *res = calloc(HOST_STR_SZ * MAX_CHANNEL_NUM, sizeof(char));
    channel_hash_t *curr_channel_wrapped, *tmp;
    HASH_ITER(hh, user->user_channels, curr_channel_wrapped, tmp)
    {
        if (strlen(res))
        {
            strcat(res, " ");
        }
        strcat(res, curr_channel_wrapped->channel->channel_name);
    }
    chilog(DEBUG, "list of user channels: %s", res);
    return res;
}

bool is_user_in_channel(channel_t *channel, user_t *user)
{
    user_hash_t *tmp_res;
    HASH_FIND_STR(channel->channel_users, user->nickname, tmp_res);
    if (tmp_res)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int add_user_to_channel_ops(channel_t *channel, user_t *user)
{
    channel_hash_t *wrapped_channel;
    HASH_FIND_STR(user->user_channels, channel->channel_name, wrapped_channel);
    wrapped_channel->is_channel_op = true;
    return 0;
}

int rm_user_from_channel_ops(channel_t *channel, user_t *user)
{
    channel_hash_t *wrapped_channel;
    HASH_FIND_STR(user->user_channels, channel->channel_name, wrapped_channel);
    wrapped_channel->is_channel_op = false;
    return 0;
}

bool is_user_channel_op(channel_t *channel, user_t *user)
{
    channel_hash_t *wrapped_channel;
    HASH_FIND_STR(user->user_channels, channel->channel_name, wrapped_channel);
    return wrapped_channel->is_channel_op;
}

int delete_user_from_channel(channel_t *channel, user_t *user)
{
    chilog(DEBUG, "Func: delete_user_from_channel");

    /* To detect whether the deletion is success */
    int prev_num_users = num_users_in_channel(channel);

    /* delete the user entry in channel */
    user_hash_t *user_wrapped_tmp;
    HASH_FIND_STR(channel->channel_users, user->nickname, user_wrapped_tmp);
    pthread_mutex_lock(&channel->channel_lock_individual);
    HASH_DEL(channel->channel_users, user_wrapped_tmp);
    pthread_mutex_unlock(&channel->channel_lock_individual);
    /* free the "wrap" */
    free(user_wrapped_tmp);

    /* delete the channel entry in user */
    channel_hash_t *channel_wrapped_tmp;
    HASH_FIND_STR(user->user_channels, channel->channel_name, channel_wrapped_tmp);
    pthread_mutex_lock(&user->user_lock_individual);
    HASH_DEL(user->user_channels, channel_wrapped_tmp);
    pthread_mutex_unlock(&user->user_lock_individual);
    /* free the "wrap" */
    free(channel_wrapped_tmp);

    if (num_users_in_channel(channel) == prev_num_users - 1)
    {
        return 0;
    }
    else
    {
        chilog(ERROR, "deletion failed, no decrement in num_users_in_channel");
        return 1;
    }
}

int send_string_to_user_channels(user_t *user, char *str)
{
    channel_hash_t *curr, *tmp;
    HASH_ITER(hh, user->user_channels, curr, tmp)
    {
        send_string_to_channel(curr->channel, str, user);
    }
    return 0;
}

int num_users_in_channel(channel_t *channel)
{
    return HASH_COUNT(channel->channel_users);
}
