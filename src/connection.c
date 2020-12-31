#include "connection.h"

connection_t *create_connection(enum connection_type type, server_t *server, int socket)
{
    connection_t *connection;
    connection = calloc(1, sizeof(connection_t));
    connection->type = type;
    connection->server = server;
    connection->socket = socket;
    pthread_mutex_init(&connection->connection_socket_lock, NULL);
    connection->connected_user = create_user(connection);
    connection->connected_remote_server = create_remote_server(connection);
    strcpy(connection->connected_user->connected_server_name, server->server_name);

    /* this mutex is in server struct, protecting num_connections */
    pthread_mutex_lock(&server->connection_lock);

    server->num_total_connection++;
    chilog(DEBUG, "num total connection increased: %d", server->num_total_connection);

    if (type == User)
    {
        server->num_user_connection++;
        chilog(DEBUG, "num user connection increased: %d", server->num_user_connection);
    }
    else if (type == Server)
    {
        server->num_server_connection++;
        chilog(DEBUG, "num server connection increased: %d", server->num_server_connection);
    }

    pthread_mutex_unlock(&server->connection_lock);

    return connection;
}

void *service_single_connection(void *args)
{
    chilog(INFO, "new thread started");

    worker_args_t *wa = (worker_args_t *) args;
    connection_t *connection_info = wa->connection;
    enum connection_type type;
    int socket;
    server_t *server;
    user_t *user;
    char message_str_received[MAX_IRC_MSG_STR_SZ];
    char *buffer = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));

    chilog(TRACE, "%d", connection_info->socket);
    type = connection_info->type;


    pthread_detach(pthread_self());
    chilog(DEBUG, "a connection thread successfully detached");

    server = connection_info->server;
    socket = connection_info->socket;

    while (1)
    {
        /* a message (command) struct to store parsed message */
        message_t *msg = calloc(1, sizeof(message_t));

        /* Note that there might be trash chars after NULL terminator
         * in res/message_str_received */
        if (get_full_msgstr(socket, &buffer, message_str_received) != 0)
        {
            chilog(ERROR, "error getting full message. closing socket.");
            msg_destroy(msg);
            close(socket);
            pthread_exit(NULL);
        }

        if (msg_from_string(msg, message_str_received) != 0)
        {
            chilog(ERROR, "error parsing message. closing socket.");
            msg_destroy(msg);
            close(socket);
            pthread_exit(NULL);
        }

        chilog(DEBUG, "messagestr %s processed", message_str_received);

        if (handle_command(server, connection_info, msg) == 1)
        {
            chilog(INFO, "thread terminated");
            pthread_exit(NULL);
        }
    }

    close(socket);
    pthread_exit(NULL);
}


int is_msgstr_ended(char *msgstr)
{
    chilog(TRACE, "is_msgstr_ended(%s)", msgstr);

    if (msgstr == NULL)
    {
        chilog(ERROR, "could not find the msgstr pointer");
        return 0;
    }

    int len = strlen(msgstr);
    if (len < 2)
    {
        return 0;
    }
    /* parse a message everytime we encounter the terminator */
    if (strstr(msgstr, "\r\n") != NULL)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int get_full_msgstr(int client_socket, char **buffer_ptr, char *res)
{
    chilog(TRACE, "calling get_full_msg_str");
    char *buffer;
    buffer = *buffer_ptr;
    /* pos to append to the current buffer; does NOT create a new str */
    char *buffer_contd = buffer + strlen(buffer);
    char *msg_end_pos;
    char *temp;

    /* used to temporarily store the return value of recv */
    int tmp_ret;
    int length;

    while (!is_msgstr_ended(buffer))
    {
        if ((tmp_ret = recv(client_socket, buffer_contd, MAX_IRC_MSG_LEN + 2, 0)) <= 0)
        {
            chilog(TRACE, "tmp_ret recvd");
            if (tmp_ret < 0)
            {
                chilog(ERROR, "error reading from socket");
            }
            else if (tmp_ret == 0)
            {
                chilog(INFO, "connection lost");
            }
            return -1;
        }
        chilog(TRACE, "partial message \"%s\" received", buffer_contd);
        chilog(TRACE, "current message in buffer: \"%s\"", buffer);

        /* update buffer_contd to the end of buffer */
        buffer_contd = buffer + strlen(buffer);
    }

    msg_end_pos = strstr(buffer, "\r\n");
    length = msg_end_pos - buffer + 2;

    temp = strdup(msg_end_pos + 2);

    *msg_end_pos = 0;

    /* Note that there might be trash chars after NULL terminator in res/msg_recvd */
    strcpy(res, buffer);

    free(buffer);
    buffer = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    *buffer_ptr = buffer;
    strcpy(buffer, temp);
    free(temp);

    chilog(INFO, "full message \"%s\" received", res);

    return 0;
}

bool send_all(int socket, void *str, size_t length, int flags)
{
    char *ptr = (char*) str;
    while (length > 0)
    {
        int len_sent = send(socket, ptr, length, flags);
        if (len_sent < 1) return false;
        ptr += len_sent;
        length -= len_sent;
    }
    return true;
}