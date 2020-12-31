 /*
 *  chirc: a simple multi-threaded IRC server
 *
 *  command structures and relating functions (reading, parsing)
 *
 *  see cmd_parsing.h for descriptions of functions, parameters, and return values.
 *
 */

/*
 *  Copyright (c) 2011-2020, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "message.h"


int msg_from_string(message_t *msg, char *s)
{
    if (s == NULL)
    {
        chilog(ERROR, "could not find message");
        return 1;
    }
    chilog(DEBUG, "parsing msg \"%s\"", s);

    /* msg_cpy to be used and "ruined" by strtok */
    char *msg_cpy = strdup(s);
    char *rest = NULL;
    char *token = NULL;
    char *prefix = NULL;

    /* parse the first word - command */
    token = strtok_r(msg_cpy, " ", &rest);
    if (token == NULL)
    {
        chilog(ERROR, "no content in msg");
        return 1;
    }

    if (token[0] == ':')
    {
        chilog(DEBUG, "prefix detected: %s", token);
        /* exclude the ':' */
        prefix = strdup(token + 1);
        token = strtok_r(NULL, " ", &rest);
        if (token == NULL)
        {
            chilog(ERROR, "could not find command");
            return 1;
        }
    }
    msg_construct(msg, prefix, token);
    chilog(DEBUG, "command parsed: \"%s\"", token);

    if (strcmp(rest, "") == 0)
    {
        chilog(DEBUG, "message with no params received: \"%s\"", token);
        free(msg_cpy);
        return 0;
    }
    /* parse long parameter */
    if (rest[0] == ':')
    {
        msg_add_param(msg, rest + 1, true);
        free(msg_cpy);
        return 0;;
    }

    /* parse the rest - parameters */
    token = strtok_r(NULL, " \r\n", &rest);

    while (token != NULL)
    {
        /* parse long parameter */
        if (rest[0] == ':')
        {
            msg_add_param(msg, token, false);
            msg_add_param(msg, rest + 1, true);
            break;
        }

        msg_add_param(msg, token, false);
        token = strtok_r(NULL, " \r\n", &rest);
    }

    free(msg_cpy);
    return 0;
}

int msg_to_string(message_t *msg, char **output_str)
{
    /* stores the string generated from the list of parameters */
    char *str_params = calloc(MAX_IRC_MSG_LEN, sizeof(char));
    if (msg->nparams == 0)
    {
        strcpy(*output_str, msg->cmd);
        chilog(DEBUG, "string successfully generated: \"%s\"", *output_str);
        return 0;
    }
    /* iterate through the list of parameters and create string */
    for (int i = 0; i < msg->nparams - 1; i++)
    {
        strcat(str_params, msg->params[i]);
        strcat(str_params, " ");
    }
    /* handle long parameter */
    if (msg->longlast)
    {
        strcat(str_params, ":");
    }
    strcat(str_params, msg->params[msg->nparams - 1]);
    chilog(TRACE, "string successfully generated from parameters: \"%s\"", str_params);

    /* handle situation when the message have no prefix */
    if (msg->prefix != NULL)
    {
        if (sprintf(*output_str, "%s %s %s\r\n", msg->prefix, msg->cmd, str_params) < 0)
        {
            chilog(ERROR, "generating string failed");
            return 1;
        }
    }
    else
    {
        if (sprintf(*output_str, "%s %s\r\n", msg->cmd, str_params) < 0)
        {
            chilog(ERROR, "generating string failed");
            return 1;
        }
    }
    chilog(DEBUG, "string successfully generated: \"%s\"", *output_str);

    return 0;
}

int msg_construct(message_t *msg, char *prefix, char *cmd)
{
    msg->nparams = 0;
    /* Note that NULL means there's no prefix, which is OK */
    if (prefix != NULL)
    {
        msg->prefix = calloc(MAX_IRC_MSG_STR_SZ, sizeof(char));
        sprintf(msg->prefix, ":%s", prefix);
    }
    msg->cmd = strdup(cmd);
    chilog(DEBUG, "new message constructed - prefix: \"%s\", cmd: \"%s\"", msg->prefix, msg->cmd);
    return 0;
}

int msg_add_param(message_t *msg, char *param, bool longlast)
{
    /* a message cannot have more than one long parameter */
    if (longlast && msg->longlast)
    {
        chilog(ERROR, "more than 1 long argument in a message");
        return 1;
    }

    msg->longlast = longlast;

    /* check if the max number of parameter is exceeded */
    if (msg->nparams > 14)
    {
        chilog(ERROR, "max number of parameters exceeded");
        return 1;
    }

    /* check if the message contains long parameter */
    if (longlast)
    {
        msg->params[msg->nparams] = strdup(param);
        chilog(TRACE, "long param: \"%s\"", msg->params[msg->nparams]);
    }
    else
    {
        msg->params[msg->nparams] = strdup(param);
        chilog(TRACE, "one more param: \"%s\"", msg->params[msg->nparams]);
    }
    /* update number of parameter */
    msg->nparams++;
    chilog(TRACE, "nparams increased to %d", msg->nparams);

    return 0;
}


int msg_destroy(message_t *msg)
{
    free(msg->cmd);
    free(msg->prefix);
    for (int i = 0; i < msg->nparams; i++)
    {
        free(msg->params[i]);
    }
    chilog(DEBUG, "message freed");
    return 0;
}
