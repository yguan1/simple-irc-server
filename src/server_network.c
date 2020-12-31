#include "server_network.h"

int connect_remote_server(server_t *local_server, char *target_server_name)
{
    remote_server_t *target_server;
    network_spec_t *target_server_spec;
    int connection_socket;
    connection_t *connection;
    socklen_t sin_size = sizeof(struct sockaddr_storage);

    target_server_spec = find_network_spec(local_server, target_server_name);
    if (target_server_spec == NULL)
    {
        chilog(ERROR, "could not find remote server with given servername %s",
               target_server_name);
        return 1;
    }

    struct addrinfo hints, // Used to provide hints to getaddrinfo()
                    *res,  // Used to return the list of addrinfo's
                    *p;    // Used to iterate over this list
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(target_server_spec->hostname, target_server_spec->port, &hints, &res) != 0)
    {
        chilog(ERROR, "getaddrinfo() failed");
        return 1;
    }

    for(p = res;p != NULL; p = p->ai_next)
    {
        /* The list could potentially include multiple entries (e.g., if a
           hostname resolves to multiple IP addresses). Here we just pick
           the first address we can connect to, although we could do
           additional filtering (e.g., we may prefer IPv6 addresses to IPv4
           addresses */

        /* Try to open a socket */
        if ((connection_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            chilog(WARNING, "Could not open socket");
            continue;
        }

        /* Try to connect. */
        if (connect(connection_socket, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(connection_socket);
            chilog(WARNING, "Could not connect to socket");
            continue;
        }

        connection =
                create_connection(Unknown, local_server, connection_socket);

        /* when creating a connection, a remote_server struct is also generated
         * we need to put the server name in it */
        target_server = connection->connected_remote_server;
        strcpy(target_server->servername, target_server_name);
        target_server->is_passive = true;

        /* If we make it this far, we've connected successfully. Don't check any more entries */
        break;
    }

    freeaddrinfo(res);

    /* Now the connection is established, and we will need to authenticate
     * with the connected remote server */

    message_t *pass_msg = calloc(1, sizeof(message_t));
    message_t *server_msg = calloc(1, sizeof(message_t));
    char *pass_reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
    char *server_reply = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));

    msg_construct(pass_msg, NULL, "PASS");
    msg_add_param(pass_msg, target_server_spec->passwd, false);
    msg_add_param(pass_msg, "0210", false);
    msg_add_param(pass_msg, local_server->version, false);
    msg_to_string(pass_msg, &pass_reply);
    send_string_to_remote_server(target_server, pass_reply);

    msg_construct(server_msg, NULL, "SERVER");
    msg_add_param(server_msg, local_server->server_name, false);
    msg_add_param(server_msg, "hello there", true);
    msg_to_string(server_msg, &server_reply);
    send_string_to_remote_server(target_server, server_reply);

    msg_destroy(pass_msg);
    msg_destroy(server_msg);
    free(pass_reply);
    free(server_reply);

    pthread_t worker_thread;
    worker_args_t *wa = calloc(1, sizeof(worker_args_t));
    wa->connection = connection;
    if (pthread_create(&worker_thread, NULL,
                        service_single_connection, wa) != 0)
    {
        chilog(ERROR, "Could not create a worker thread");
        close(connection_socket);
        pthread_exit(NULL);
    }

    /* After sending PASS & SERVER, this connection is passed over to a new
     * thread running service_single_connection; the remote_server struct is
     * not added to the local server until a reply is received via the new
     * thread. The original thread returns here, ready for the next cmd */
    return 0;
}

remote_server_t *create_remote_server(connection_t *connection)
{
    remote_server_t *remote_server = calloc(1, sizeof(remote_server_t));
    remote_server->connection_to_local = connection;
    pthread_mutex_init(&remote_server->remote_server_lock_individual, NULL);
    return remote_server;
}

int add_remote_server_to_server(server_t *server, remote_server_t *remote_server)
{
    pthread_mutex_lock(&server->remote_server_lock);
    HASH_ADD_STR(server->all_remote_servers, servername, remote_server);
    pthread_mutex_unlock(&server->remote_server_lock);
    chilog(DEBUG, "remote_server \"%s\" added to server hashtable", remote_server->servername);
    return 0;
}

int num_remote_servers(remote_server_t *all_remote_servers)
{
    return HASH_COUNT(all_remote_servers);
}

remote_server_t *find_remote_server(remote_server_t *all_remote_servers, char *servername)
{
    remote_server_t *remote_server;
    /* this function returns NULL if remote_server is not found */
    HASH_FIND_STR(all_remote_servers, servername, remote_server);
    return remote_server;
}

int delete_remote_server(remote_server_t **all_remote_servers, remote_server_t *remote_server)
{
    HASH_DEL(*all_remote_servers, remote_server);
    chilog(DEBUG, "remote_server \"%s\" deleted from hashtable", remote_server->servername);

    /* Don't free remote_server yet! Still gonna be used in send_quit_message */
    /* free(remote_server); */
}

int send_string_to_remote_server(remote_server_t *remote_server, char* str)
{
    chilog(DEBUG, "sending str ||| %s ||| to remote_server %s", str,remote_server->servername);
    connection_t *connection = remote_server->connection_to_local;
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
    chilog(INFO, "string ||| %s ||| sent to remote_server %s", str, remote_server->servername);
    return 0;
}

int send_string_to_all_remote_servers(server_t *local_server, char *str)
{
    remote_server_t *curr_remote_server, *tmp;
    HASH_ITER(hh, local_server->all_remote_servers, curr_remote_server, tmp)
    {
        send_string_to_remote_server(curr_remote_server, str);
    }
    return 0;
}