/*!
 * \file netopeerguid.h
 * \brief NETCONF daemon header for NetopeerGUI
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \date 2011
 * \date 2012
 * \date 2013
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2011-2015 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */
#ifndef _NETOPEERGUID_H
#define _NETOPEERGUID_H

#include <pthread.h>
#include <json.h>
#include <libyang/libyang.h>

#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))

/**
 * \brief Check if pointer is not NULL, free memory and set pointer to NULL
 */
#define CHECK_AND_FREE(pointer) if (pointer != NULL) { free(pointer); pointer = NULL; }

typedef struct notification {
    time_t eventtime;
    char* content;
} notification_t;

struct session_with_mutex {
    struct nc_session *session; /**< netconf session */
    unsigned int session_key;    /**< unique session identifier throughout all the sessions */
    notification_t *notifications;
    int notif_count;
    json_object *hello_message;
    char ntfc_subscribed; /**< 0 when notifications are not subscribed */
    char closed; /**< 0 when session is terminated */
    time_t last_activity;
    pthread_mutex_t lock; /**< mutex protecting the session from multiple access */

    struct session_with_mutex *prev;
    struct session_with_mutex *next;
};

struct pass_to_thread {
    int client; /**< opened socket */
    struct session_with_mutex *netconf_sessions_list; /**< ?? */
};

extern pthread_rwlock_t session_lock; /**< mutex protecting netconf_session_list from multiple access errors */

extern pthread_key_t err_reply_key;
extern pthread_mutex_t json_lock;

json_object *create_error_reply(const char *errmess);

#define DEBUG(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while (0);

#define ERROR(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while (0);

#define GETSPEC_ERR_REPLY \
json_object **err_reply_p = (json_object **) pthread_getspecific(err_reply_key); \
json_object *err_reply = ((err_reply_p != NULL)?(*err_reply_p):NULL);

#define CHECK_ERR_SET_REPLY \
if (reply == NULL) { \
    GETSPEC_ERR_REPLY \
    if (err_reply != NULL) { \
        /* use filled err_reply from libnetconf's callback */ \
        reply = err_reply; \
    } \
}

#define CHECK_ERR_SET_REPLY_ERR(errmsg) \
if (reply == NULL) { \
    GETSPEC_ERR_REPLY \
    if (err_reply == NULL) { \
        reply = create_error_reply(errmsg); \
    } else { \
        /* use filled err_reply from libnetconf's callback */ \
        reply = err_reply; \
    } \
}
void create_err_reply_p();
void clean_err_reply();
void free_err_reply();

NC_MSG_TYPE netconf_send_recv_timed(struct nc_session *session, struct nc_rpc *rpc, int timeout,
                                    int strict, struct nc_reply **reply);

#endif
