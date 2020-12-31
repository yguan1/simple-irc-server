/*
 *
 *  chirc: a simple multi-threaded IRC server
 *
 *  This module provides data structure that stores message information
 *  as well as functions reading and parsing messages
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

#include "log.h"

#ifndef MESSAGE_H_
#define MESSAGE_H_

/* max string length of IRC message */
#define MAX_IRC_MSG_LEN 510
/* max string length of IRC message string */
#define MAX_IRC_MSG_STR_SZ MAX_IRC_MSG_LEN + 3
/* max number of parameter */
#define MAX_IRC_PARAM_NUM 15

typedef struct
{
    /* prefix: leading by a ':', used to indicate origin of the message */
    char *prefix;

    /* cmd: command name, the first uppercase word in an IRC message */
    char *cmd;

    /* params: the command parameters (maximum of fifteen) */
    char *params[MAX_IRC_PARAM_NUM];

    /* nparams: number of command parameters*/
    int nparams;

    /* longlast: if the message contains a long parameter */
    bool longlast;

} message_t;

/* msg_from_string - Parse a string into a message_t struct
 *
 * msg: message_t struct that stores the parsed content
 *
 * s: string to be parsed
 *
 * Returns: 0 if successed, 1 if error occured
 */
int msg_from_string(message_t *msg, char *s);

/* msg_to_string - Translate message_t struct into string
 *
 * msg: message_t struct to be translated
 *
 * s: pointer to where is returning string will be stored
 *
 * Returns: 0 if successed, 1 if error occured
 */
int msg_to_string(message_t *msg, char **s);

/* msg_construct - Construct a message_t struct
 *
 * msg: message_t struct to be constructed
 *
 * prefix: prefix of the message
 *
 * cmd: command name of the message
 *
 * Returns: 0 if successed, 1 if error occured
 */
int msg_construct(message_t *msg, char *prefix, char *cmd);

/* msg_construct - Adding one parameter to the struct message_t
 *
 * msg: message_t struct to be modified
 *
 * param: the parameter to be added
 *
 * longlast: if the parameter is a long parameter
 *
 * Returns: 0 if successed, 1 if error occured
 */
int msg_add_param(message_t *msg, char *param, bool longlast);

/* msg_construct - Construct a message_t struct
 *
 * msg: message_t struct to be freed
 *
 * Returns: 0 if successed, 1 if error occured
 */
int msg_destroy(message_t *msg);

#endif
