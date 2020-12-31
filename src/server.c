#include "server.h"

/* current_time - utility function that outputs current time in desired format
 *
 * server: the string where the formatted time will be returned to
 *
 * Returns: none
 */
void current_time(char *res);

/* setup_server - set up a server with the given port information
 * Specifically, with port information, bind to a socket and start listening
 *
 * server: the server struct with starting info including port
 *
 * Returns: none
 */
void setup_server(server_t *server)
{
    chilog(TRACE, "setting up server");
    char *port;
    int server_socket;
    int client_socket;
    struct addrinfo hints, *res, *p;
    int yes = 1;

    port = server->port;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &res) != 0)
    {
        chilog(ERROR, "getaddrinfo() failed");
        exit(-1);
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        if ((server_socket = socket(p->ai_family, p->ai_socktype,
                                    p->ai_protocol)) == -1)
        {
            chilog(ERROR, "Could not open socket");
            continue;
        }

        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR,
                       &yes, sizeof(int)) == -1)
        {
            chilog(ERROR, "Socket setsockopt() failed");
            close(server_socket);
            continue;
        }

        if (bind(server_socket, p->ai_addr, p->ai_addrlen) == -1)
        {
            chilog(ERROR, "Socket bind() failed");
            close(server_socket);
            continue;
        }

        if (listen(server_socket, 5) == -1)
        {
            chilog(ERROR, "Socket listen() failed");
            close(server_socket);
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL)
    {
        chilog(ERROR, "Could not find a socket to bind to.");
        exit(-1);
    }

    server->server_socket = server_socket;
    chilog(INFO, "server socket set up at %d", server->server_socket);
}

server_t *create_server(server_wa_t *server_wa)
{
    chilog(TRACE, "creating server");
    network_spec_t *spec_tmp;
    server_t *server;
    server = calloc(1, sizeof(server_t));

    strcpy(server->version, SERVER_VERSION);
    server->passwd = server_wa->passwd;
    server->network_file = server_wa->network_file;
    server->server_name = server_wa->server_name;
    server->port = server_wa->port;
    if (strcmp(server->network_file, "") != 0)
    {
        /* in case the port is not specified, we need to find it
         * in the network file */
        parse_network_file(server);
        spec_tmp = find_network_spec(server, server->server_name);
        server->port = spec_tmp->port;
        server->connection_passwd = spec_tmp->passwd;
    }
    server->num_total_connection = 0;
    server->num_user_connection = 0;
    server->num_server_connection = 0;
    server->server_hostname = calloc(HOST_STR_SZ, sizeof(char));
    gethostname(server->server_hostname, sizeof(server->server_hostname));
    /* set default server name as the hostname */
    if (server->server_name == NULL)
    {
        server->server_name = strdup(server->server_hostname);
    }

    current_time(server->time_created);

    pthread_mutex_init(&server->server_lock, NULL);
    pthread_mutex_init(&server->user_lock, NULL);
    pthread_mutex_init(&server->channel_lock, NULL);
    pthread_mutex_init(&server->connection_lock, NULL);
    pthread_mutex_init(&server->remote_server_lock, NULL);

    setup_server(server);

    return server;
}

void run_server(server_t *server)
{
    int client_socket;
    int server_socket = server->server_socket;
    struct sockaddr_storage *client_addr;
    socklen_t sin_size = sizeof(struct sockaddr_storage);

    while (1)
    {
        client_addr = calloc(1, sin_size);
        if ((client_socket = accept(server_socket, (struct sockaddr *)
                                    client_addr, &sin_size)) == -1)
        {
            free(client_addr);
            chilog(ERROR, "Could not accept() connection");
            continue;
        }
        chilog(INFO, "connected at socket %d", client_socket);

        connection_t *connection =
            create_connection(Unknown, server, client_socket);

        /* get the hostname and servname using known client_addr */
        getnameinfo((struct sockaddr *)client_addr, sin_size,
                    connection->connected_user->hostname,
                    sizeof(connection->connected_user->hostname),
                    connection->connected_user->servname,
                    sizeof(connection->connected_user->servname),
                    0);

        chilog(DEBUG, "client hostname: %s",
        connection->connected_user->hostname);

        pthread_t worker_thread;
        worker_args_t *wa = calloc(1, sizeof(worker_args_t));
        wa->connection = connection;
        if (pthread_create(&worker_thread, NULL,
                           service_single_connection, wa) != 0)
        {
            chilog(ERROR, "Could not create a worker thread");
            free(client_addr);
            close(client_socket);
            pthread_exit(NULL);
        }

        free(client_addr);
    }

}

int send_string_to_server(server_t *server, char* str, user_t *skipped_user)
{
    bool flag_all_sent = true;
    user_t *curr_user, *tmp;
    HASH_ITER(hh, server->all_users, curr_user, tmp)
    {
        /* Skip the sender themselves; safe even if NULL */
        if (curr_user == skipped_user)
        {
            continue;
        }
        if (send_string_to_user(curr_user, str) != 0)
        {
            flag_all_sent = false;
        }
    }
    if (!flag_all_sent)
    {
        chilog(ERROR, "server send failed on some connections");
        return 1;
    }
    return 0;
}

void delete_server(server_t *server)
{
    free(server->port);
    free(server->passwd);
    free(server->server_name);
    free(server->network_file);
    free(server->server_hostname);
}

void current_time(char *res)
{
    time_t timer;
    struct tm* tm_info;

    timer = time(NULL);
    tm_info = localtime(&timer);

    strftime(res, 20, "%Y-%m-%d %H:%M:%S", tm_info);
    return;
}

int parse_network_file(server_t *server)
{
    FILE *fp;
    int str_sz = SERVER_STR_SZ + HOST_STR_SZ + PORT_STR_SZ + PASSWD_STR_SZ + 4;
    char line[str_sz];
    char *rest, *token;
    char servername[SERVER_STR_SZ];
    char hostname[HOST_STR_SZ];
    char port[PORT_STR_SZ];
    char passwd[PASSWD_STR_SZ];
    network_spec_t *new_server_info;

    server->network_spec = NULL;

    fp = fopen(server->network_file, "r");
    chilog(DEBUG, "reading from network file");
    while (fgets(line, str_sz, fp) != NULL)
    {
        chilog(DEBUG, "line read: %s", line);
        token = strtok_r(line, ",\r\n", &rest);
        strcpy(servername, token);
        token = strtok_r(NULL, ",\r\n", &rest);
        strcpy(hostname, token);
        token = strtok_r(NULL, ",\r\n", &rest);
        strcpy(port, token);
        token = strtok_r(NULL, ",\r\n", &rest);
        strcpy(passwd, token);
        token = strtok_r(NULL, ",\r\n", &rest);

        chilog(DEBUG, "servername: %s, hostname: %s, port: %s, passwd: %s",
               servername, hostname, port, passwd);

        new_server_info = calloc(1, sizeof(network_spec_t));
        strcpy(new_server_info->servername, servername);
        strcpy(new_server_info->hostname, hostname);
        strcpy(new_server_info->port, port);
        strcpy(new_server_info->passwd, passwd);

        HASH_ADD_STR(server->network_spec, servername, new_server_info);
        chilog(INFO, "network spec parsed 1 line and added to memory - "
                    "servername: %s, hostname: %s, port: %s, passwd: %s",
                    servername, hostname, port, passwd);
    }

    fclose(fp);
    return 0;
}

network_spec_t *find_network_spec(server_t *local_server, char *servername)
{
    network_spec_t *network_spec_single;
    HASH_FIND_STR(local_server->network_spec, servername, network_spec_single);
    return network_spec_single;
}