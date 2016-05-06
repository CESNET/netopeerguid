/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2011 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <nc_client.h>
#include <libwebsockets.h>

#include "notification_server.h"
#include "netopeerguid.h"
#include "../config.h"

#ifdef TEST_NOTIFICATION_SERVER
static int force_exit = 0;
#endif

#if defined(TEST_NOTIFICATION_SERVER) || defined(WITH_NOTIFICATIONS)
static int max_poll_elements;

static struct pollfd *pollfds;
static int *fd_lookup;
static int count_pollfds;
static struct lws_context *context = NULL;

extern struct session_with_mutex *netconf_sessions_list;
static pthread_key_t thread_key;

/*
 * This demo server shows how to use libwebsockets for one or more
 * websocket protocols in the same server
 *
 * It defines the following websocket protocols:
 *
 *  dumb-increment-protocol:  once the socket is opened, an incrementing
 *              ascii string is sent down it every 50ms.
 *              If you send "reset\n" on the websocket, then
 *              the incrementing number is reset to 0.
 *
 *  lws-mirror-protocol: copies any received packet to every connection also
 *              using this protocol, including the sender
 */

enum demo_protocols {
    /* always first */
    PROTOCOL_HTTP = 0,

    PROTOCOL_NOTIFICATION,

    /* always last */
    DEMO_PROTOCOL_COUNT
};

#define SERVER_CERT_DIR "."
#define SERVER_CERT "server.crt"
#define SERVER_KEY "server.key"

/*
 * We take a strict whitelist approach to stop ../ attacks
 */

struct serveable {
    const char *urlpath;
    const char *mimetype;
};

static const struct serveable whitelist[] = {
    { "/favicon.ico", "image/x-icon" },
    { "/libwebsockets.org-logo.png", "image/png" },

    /* last one is the default served if no match */
    { "/test.html", "text/html" },
};

struct per_session_data__http {
    int fd;
};

/* this protocol server (always the first one) just knows how to do HTTP */

static int callback_http(struct lws *wsi,
        enum lws_callback_reasons reason, void *user,
                               void *in, size_t UNUSED(len))
{
    char client_name[128];
    char client_ip[128];
    char buf[256];
    int n, m;
    static unsigned char buffer[4096];
    struct per_session_data__http *pss = (struct per_session_data__http *)user;
    struct lws_pollargs *pa = (struct lws_pollargs *)in;

    switch (reason) {
    case LWS_CALLBACK_HTTP:
        for (n = 0; n < (signed) (sizeof(whitelist) / sizeof(whitelist[0]) - 1); n++)
            if (in && strcmp((const char *)in, whitelist[n].urlpath) == 0)
                break;

        sprintf(buf, SERVER_CERT_DIR "%s", whitelist[n].urlpath);

        if (lws_serve_http_file(wsi, buf, whitelist[n].mimetype, NULL, 0))
            return -1; /* through completion or error, close the socket */

        /*
         * notice that the sending of the file completes asynchronously,
         * we'll get a LWS_CALLBACK_HTTP_FILE_COMPLETION callback when
         * it's done
         */

        break;

    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
//      lwsl_info("LWS_CALLBACK_HTTP_FILE_COMPLETION seen\n");
        /* kill the connection after we sent one file */
        return -1;

    case LWS_CALLBACK_HTTP_WRITEABLE:
        /*
         * we can send more of whatever it is we were sending
         */

        do {
            n = read(pss->fd, buffer, sizeof buffer);
            /* problem reading, close conn */
            if (n < 0)
                goto bail;
            /* sent it all, close conn */
            if (n == 0)
                goto bail;
            /*
             * because it's HTTP and not websocket, don't need to take
             * care about pre and postamble
             */
            m = lws_write(wsi, buffer, n, LWS_WRITE_HTTP);
            if (m < 0)
                /* write failed, close conn */
                goto bail;
            if (m != n)
                /* partial write, adjust */
                lseek(pss->fd, m - n, SEEK_CUR);

        } while (!lws_send_pipe_choked(wsi));
        lws_callback_on_writable(wsi);
        break;

bail:
        close(pss->fd);
        return -1;

    case LWS_CALLBACK_LOCK_POLL:
        /*
         * lock mutex to protect pollfd state
         * called before any other POLL related callback
         */
        break;

    case LWS_CALLBACK_UNLOCK_POLL:
        /*
         * unlock mutex to protect pollfd state when
         * called after any other POLL related callback
         */
        break;

    /*
     * callback for confirming to continue with client IP appear in
     * protocol 0 callback since no websocket protocol has been agreed
     * yet.  You can just ignore this if you won't filter on client IP
     * since the default uhandled callback return is 0 meaning let the
     * connection continue.
     */

    case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
        lws_get_peer_addresses(wsi, (int)(long)in, client_name,
                 sizeof(client_name), client_ip, sizeof(client_ip));

        //fprintf(stderr, "Received network connect from %s (%s)\n", client_name, client_ip);
        /* if we returned non-zero from here, we kill the connection */
        break;

    /*
     * callbacks for managing the external poll() array appear in
     * protocol 0 callback
     */

    case LWS_CALLBACK_ADD_POLL_FD:
        if (count_pollfds >= max_poll_elements) {
            lwsl_err("LWS_CALLBACK_ADD_POLL_FD: too many sockets to track\n");
            return 1;
        }

        fd_lookup[pa->fd] = count_pollfds;
        pollfds[count_pollfds].fd = pa->fd;
        pollfds[count_pollfds].events = pa->events;
        pollfds[count_pollfds++].revents = 0;
        break;

    case LWS_CALLBACK_DEL_POLL_FD:
        if (!--count_pollfds)
            break;
        m = fd_lookup[pa->fd];
        /* have the last guy take up the vacant slot */
        pollfds[m] = pollfds[count_pollfds];
        fd_lookup[pollfds[count_pollfds].fd] = m;
        break;

    case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
        pollfds[fd_lookup[pa->fd]].events = pa->events;
        break;


    default:
        break;
    }

    return 0;
}

/*
 * one of these is auto-created for each connection and a pointer to the
 * appropriate instance is passed to the callback in the user parameter
 *
 * for this example protocol we use it to individualize the count for each
 * connection.
 */

struct per_session_data__notif_client {
    int number;
    char *session_id;
    struct nc_session *session;
};

struct session_with_mutex *get_ncsession_from_sid(const char *session_id)
{
    struct session_with_mutex *locked_session = NULL;
    if (session_id == NULL) {
        return (NULL);
    }
    for (locked_session = netconf_sessions_list;
         locked_session && (nc_session_get_id(locked_session->session) == (unsigned)atoi(session_id));
         locked_session = locked_session->next);
    return locked_session;
}

/* rpc parameter is freed after the function call */
static int send_recv_process(struct nc_session *session, const char* UNUSED(operation), struct nc_rpc* rpc)
{
    struct nc_reply *reply = NULL;
    char *data = NULL;
    int ret = EXIT_SUCCESS;

    /* send the request and get the reply */
    switch (netconf_send_recv_timed(session, rpc, 50000, 0, &reply)) {
    case NC_MSG_ERROR:
        if (nc_session_get_status(session) != NC_STATUS_RUNNING) {
            ERROR("notifications: receiving rpc-reply failed.");
            //cmd_disconnect(NULL);
            ret = EXIT_FAILURE;
            break;
        }
        ERROR("notifications: Unknown error occurred.");
        ret = EXIT_FAILURE;
        break;
    case NC_MSG_NONE:
        /* error occurred, but processed by callback */
        break;
    case NC_MSG_REPLY:
        switch (reply->type) {
        case NC_RPL_OK:
            break;
        case NC_RPL_DATA:
            lyd_print_mem(&data, ((struct nc_reply_data *)reply)->data, LYD_JSON, 0);
            DEBUG("notifications: recv: %s.", data);
            free(data);
            break;
        case NC_RPL_ERROR:
            /* wtf, you shouldn't be here !?!? */
            DEBUG("notifications: operation failed, but rpc-error was not processed.");
            ret = EXIT_FAILURE;
            break;
        default:
            DEBUG("notifications: unexpected operation result.");
            ret = EXIT_FAILURE;
            break;
        }
        break;
    default:
        DEBUG("notifications: Unknown error occurred.");
        ret = EXIT_FAILURE;
        break;
    }
    nc_rpc_free(rpc);
    nc_reply_free(reply);

    return (ret);
}

/**
 * \brief Callback to store incoming notification
 * \param [in] eventtime - time when notification occured
 * \param [in] content - content of notification
 */
static void notification_fileprint(struct nc_session *session, const struct nc_notif *notif)
{
    time_t eventtime;
    struct session_with_mutex *target_session = NULL;
    notification_t *ntf = NULL;
    const char *session_id = NULL;
    char *content;
    (void)session;

    eventtime = nc_datetime2time(notif->datetime);
    lyd_print_mem(&content, notif->tree, LYD_JSON, 0);

    DEBUG("Accepted notif: %lu %s\n", (unsigned long int) eventtime, content);

    session_id = pthread_getspecific(thread_key);
    DEBUG("notification: fileprint getspecific (%s)", session_id);
    if (pthread_rwlock_wrlock(&session_lock) != 0) {
        ERROR("notifications: Error while locking rwlock");
        free(content);
        return;
    }
    DEBUG("Get session with mutex from key %s.", session_id);
    target_session = get_ncsession_from_sid(session_id);
    if (target_session == NULL) {
        ERROR("notifications: no session found last_session_key (%s)", session_id);
        free(content);
        goto unlock_glob;
    }
    if (pthread_mutex_lock(&target_session->lock) != 0) {
        ERROR("notifications: Error while locking rwlock");
    }

    DEBUG("notification: ready to push to notifications queue");
    if (target_session->notif_count < NOTIFICATION_QUEUE_SIZE) {
        ++target_session->notif_count;
        target_session->notifications = realloc(target_session->notifications,
                                                target_session->notif_count * sizeof *target_session->notifications);
        if (target_session->notifications) {
            ntf = target_session->notifications + target_session->notif_count - 1;
        }
    }
    if (ntf == NULL) {
        ERROR("notifications: Failed to allocate element ");
        free(content);
        goto unlock_all;
    }
    ntf->eventtime = eventtime;
    ntf->content = content;

    DEBUG("added notif to queue %u (%s)", (unsigned int) ntf->eventtime, "notification");

unlock_all:
    if (pthread_mutex_unlock(&target_session->lock) != 0) {
        ERROR("notifications: Error while unlocking rwlock");
    }
unlock_glob:
    if (pthread_rwlock_unlock(&session_lock) != 0) {
        ERROR("notifications: Error while locking rwlock");
    }
}

int notif_subscribe(struct session_with_mutex *locked_session, const char *session_id, time_t start_time, time_t stop_time)
{
    time_t start = -1;
    time_t stop = -1;
    char *stream = NULL;
    struct nc_rpc *rpc = NULL;
    struct nc_session *session;

    DEBUG("notif_subscribe");
    if (locked_session == NULL) {
        DEBUG("notifications: no locked_session was given.");
        /* Close notification client */
        return -1;
    }

    pthread_mutex_lock(&locked_session->lock);
    session = locked_session->session;

    start = time(NULL) + start_time;
    stop = time(NULL) + stop_time;
    start = 0;
    stop = 0;
    DEBUG("notifications: history: %u %u", (unsigned int) start, (unsigned int) stop);

    if (session == NULL) {
        ERROR("notifications: NETCONF session not established.");
        goto operation_failed;
    }

    /* check times */
    if (start != -1 && stop != -1 && start > stop) {
        ERROR("notifications: Subscription start time must be lower than the end time.");
        goto operation_failed;
    }

    DEBUG("Prepare to execute subscription.");
    /* create requests */
    rpc = nc_rpc_subscribe(stream, NULL, (start_time == -1) ? NULL : nc_time2datetime(start, NULL),
                           (stop_time == 0) ? NULL : nc_time2datetime(stop, NULL), NC_PARAMTYPE_CONST);
    if (rpc == NULL) {
        ERROR("notifications: creating an rpc request failed.");
        goto operation_failed;
    }

    DEBUG("Send NC subscribe.");
    create_err_reply_p();
    if (send_recv_process(session, "subscribe", rpc) != 0) {
        ERROR("Subscription RPC failed.");
        goto operation_failed;
    }

    GETSPEC_ERR_REPLY
    if (err_reply != NULL) {
                free_err_reply();
                ERROR("RPC-Error received and cleaned, because we can't send it anywhere.");
                goto operation_failed;
    }

    rpc = NULL; /* just note that rpc is already freed by send_recv_process() */
    locked_session->ntfc_subscribed = 1;

    DEBUG("notifications: creating libnetconf notification thread (%s).", session_id);

    pthread_mutex_unlock(&locked_session->lock);

    /* store hash identification of netconf session for notifications printing callback */
    if (pthread_setspecific(thread_key, session_id) != 0) {
        ERROR("notifications: cannot set thread-specific hash value.");
    }

    DEBUG("Create notification_thread.");
    nc_recv_notif_dispatch(session, notification_fileprint);
    DEBUG("Subscription finished.");
    return 0;

operation_failed:
    pthread_mutex_unlock(&locked_session->lock);
    return -1;
}

static int callback_notification(struct lws *wsi,
            enum lws_callback_reasons reason,
            void *user, void *in, size_t len)
{
    int n = 0, m = 0, i;
    unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 40960 + LWS_SEND_BUFFER_POST_PADDING];
    unsigned char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];
    struct per_session_data__notif_client *pss = (struct per_session_data__notif_client *)user;

    switch (reason) {
    case LWS_CALLBACK_ESTABLISHED:
        DEBUG("ntf_prot clb LWS_CALLBACK_ESTABLISHED");
        break;
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLIENT_CONNECTION_ERROR");
        break;
    case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH");
        break;
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLIENT_ESTABLISHED");
        break;
    case LWS_CALLBACK_CLOSED:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLOSED");
        break;
    case LWS_CALLBACK_RECEIVE:
        DEBUG("ntf_prot clb LWS_CALLBACK_RECEIVE");
        break;
    case LWS_CALLBACK_RECEIVE_PONG:
        DEBUG("ntf_prot clb LWS_CALLBACK_RECEIVE_PONG");
        break;
    case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLIENT_RECEIVE_PONG");
        break;
    case LWS_CALLBACK_CLIENT_RECEIVE:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLIENT_RECEIVE");
        break;
    case LWS_CALLBACK_CLIENT_WRITEABLE:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLIENT_WRITEABLE");
        break;
    case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
        DEBUG("ntf_prot clb LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP");
        break;
    case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLOSED_CLIENT_HTTP");
        break;
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
        DEBUG("ntf_prot clb LWS_CALLBACK_RECEIVE_CLIENT_HTTP");
        break;
    case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
        DEBUG("ntf_prot clb LWS_CALLBACK_COMPLETED_CLIENT_HTTP");
        break;
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
        DEBUG("ntf_prot clb LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ");
        break;
    case LWS_CALLBACK_HTTP:
        DEBUG("ntf_prot clb LWS_CALLBACK_HTTP");
        break;
    case LWS_CALLBACK_HTTP_BODY:
        DEBUG("ntf_prot clb LWS_CALLBACK_HTTP_BODY");
        break;
    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
        DEBUG("ntf_prot clb LWS_CALLBACK_HTTP_BODY_COMPLETION");
        break;
    case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
        DEBUG("ntf_prot clb LWS_CALLBACK_FILTER_HTTP_CONNECTION");
        break;
    case LWS_CALLBACK_CLOSED_HTTP:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLOSED_HTTP");
        break;
    case LWS_CALLBACK_HTTP_WRITEABLE:
        DEBUG("ntf_prot clb LWS_CALLBACK_HTTP_WRITEABLE");
        break;
    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
        DEBUG("ntf_prot clb LWS_CALLBACK_HTTP_FILE_COMPLETION");
        break;
    case LWS_CALLBACK_SERVER_WRITEABLE:
        DEBUG("ntf_prot clb LWS_CALLBACK_SERVER_WRITEABLE");
        break;
    case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
        DEBUG("ntf_prot clb LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED");
        break;
    case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
        DEBUG("ntf_prot clb LWS_CALLBACK_FILTER_NETWORK_CONNECTION");
        break;
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
        DEBUG("ntf_prot clb LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION");
        break;
    case LWS_CALLBACK_WSI_CREATE:
        DEBUG("ntf_prot clb LWS_CALLBACK_WSI_CREATE");
        break;
    case LWS_CALLBACK_WSI_DESTROY:
        DEBUG("ntf_prot clb LWS_CALLBACK_WSI_DESTROY");
        break;
    case LWS_CALLBACK_GET_THREAD_ID:
        DEBUG("ntf_prot clb LWS_CALLBACK_GET_THREAD_ID");
        break;
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
        DEBUG("ntf_prot clb LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS");
        break;
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
        DEBUG("ntf_prot clb LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS");
        break;
    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
        DEBUG("ntf_prot clb LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION");
        break;
    case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY:
        DEBUG("ntf_prot clb LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY");
        break;
    case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER");
        break;
    case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
        DEBUG("ntf_prot clb LWS_CALLBACK_CONFIRM_EXTENSION_OKAY");
        break;
    case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
        DEBUG("ntf_prot clb LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED");
        break;
    case LWS_CALLBACK_PROTOCOL_INIT:
        DEBUG("ntf_prot clb LWS_CALLBACK_PROTOCOL_INIT");
        break;
    case LWS_CALLBACK_PROTOCOL_DESTROY:
        DEBUG("ntf_prot clb LWS_CALLBACK_PROTOCOL_DESTROY");
        break;
    case LWS_CALLBACK_ADD_POLL_FD:
        DEBUG("ntf_prot clb LWS_CALLBACK_ADD_POLL_FD");
        break;
    case LWS_CALLBACK_DEL_POLL_FD:
        DEBUG("ntf_prot clb LWS_CALLBACK_DEL_POLL_FD");
        break;
    case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
        DEBUG("ntf_prot clb LWS_CALLBACK_CHANGE_MODE_POLL_FD");
        break;
    case LWS_CALLBACK_LOCK_POLL:
        DEBUG("ntf_prot clb LWS_CALLBACK_LOCK_POLL");
        break;
    case LWS_CALLBACK_UNLOCK_POLL:
        DEBUG("ntf_prot clb LWS_CALLBACK_UNLOCK_POLL");
        break;
    case LWS_CALLBACK_USER:
        DEBUG("ntf_prot clb LWS_CALLBACK_USER");
        break;
    case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
        DEBUG("ntf_prot clb LWS_CALLBACK_WS_PEER_INITIATED_CLOSE");
        break;
    case LWS_CALLBACK_WS_EXT_DEFAULTS:
        DEBUG("ntf_prot clb LWS_CALLBACK_WS_EXT_DEFAULTS");
        break;
    case LWS_CALLBACK_CGI:
        DEBUG("ntf_prot clb LWS_CALLBACK_CGI");
        break;
    case LWS_CALLBACK_CGI_TERMINATED:
        DEBUG("ntf_prot clb LWS_CALLBACK_CGI_TERMINATED");
        break;
    case LWS_CALLBACK_CGI_STDIN_DATA:
        DEBUG("ntf_prot clb LWS_CALLBACK_CGI_STDIN_DATA");
        break;
    case LWS_CALLBACK_CGI_STDIN_COMPLETED:
        DEBUG("ntf_prot clb LWS_CALLBACK_CGI_STDIN_COMPLETED");
        break;
    }

    switch (reason) {
    case LWS_CALLBACK_ESTABLISHED:
        DEBUG("notification client connected.");
        break;

    case LWS_CALLBACK_SERVER_WRITEABLE:
        if (pss->session_id == NULL) {
            return 0;
        }
        //DEBUG("Callback server writeable.");
        //DEBUG("lock session lock.");
        if (pthread_rwlock_wrlock(&session_lock) != 0) {
            DEBUG("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
            return -1;
        }
        //DEBUG("get session_with_mutex for %s.", pss->session_id);
        struct session_with_mutex *ls = get_ncsession_from_sid(pss->session_id);
        if (ls == NULL) {
            DEBUG("notification: session not found");
            if (pthread_rwlock_unlock (&session_lock) != 0) {
                DEBUG("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
                return -1;
            }
            return -1;
        }
        pthread_mutex_lock(&ls->lock);
        if (pthread_rwlock_unlock(&session_lock) != 0) {
            DEBUG("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        }

        //DEBUG("check for closed session.");
        if (ls->closed == 1) {
            DEBUG("unlock session key.");
            if (pthread_rwlock_unlock (&session_lock) != 0) {
                DEBUG("Error while unlocking unlock: %d (%s)", errno, strerror(errno));
                return -1;
            }
            return -1;
        }
        //DEBUG("lock private lock.");
        notification_t *notif = NULL;

        if (ls->notif_count) {
            DEBUG("notification: POP notifications for session");
            for (i = ls->notif_count; i; --i) {
                notif = ls->notifications + i - 1;

                n = 0;
                pthread_mutex_lock(&json_lock);
                json_object *notif_json = json_object_new_object();
                json_object_object_add(notif_json, "eventtime", json_object_new_int64(notif->eventtime));
                json_object_object_add(notif_json, "content", json_object_new_string(notif->content));
                pthread_mutex_unlock(&json_lock);

                const char *msgtext = json_object_to_json_string(notif_json);

                //n = sprintf((char *)p, "{\"eventtime\": \"%s\", \"content\": \"notification\"}", t);
                n = sprintf((char *)p, "%s", msgtext);
                DEBUG("ws send %dB in %lu", n, sizeof(buf));
                m = lws_write(wsi, p, n, LWS_WRITE_TEXT);
                if (lws_send_pipe_choked(wsi)) {
                    lws_callback_on_writable(wsi);
                    break;
                }

                pthread_mutex_lock(&json_lock);
                json_object_put(notif_json);
                pthread_mutex_unlock(&json_lock);
                free(notif->content);
            }
            ls->notif_count = 0;
            free(ls->notifications);
            ls->notifications = NULL;

            DEBUG("notification: POP notifications done");
        }

        //DEBUG("unlock private lock");
        if (pthread_mutex_unlock(&ls->lock) != 0) {
            DEBUG("notification: cannot unlock session");
        }
        //DEBUG("unlock session lock");

        if (m < n) {
            DEBUG("ERROR %d writing to di socket.", n);

            return -1;
        }
        break;

    case LWS_CALLBACK_RECEIVE:
        DEBUG("Callback receive.");
        DEBUG("received: (%s)", (char *)in);
        if (pss->session_id == NULL) {
            char *sid_end;
            int start = -1;
            time_t stop = time(NULL) + 30;

            sid_end = strchr(in, ' ');
            pss->session_id = strndup(in, sid_end - (char *)in);

            ++sid_end;
            sscanf(sid_end, "%d %d", (int *) &start, (int *) &stop);
            DEBUG("notification: SID (%s) from (%s) (%i,%i)", pss->session_id, (char *) in, (int) start, (int) stop);

            DEBUG("lock session lock");
            if (pthread_rwlock_rdlock (&session_lock) != 0) {
                DEBUG("Error while locking rwlock: %d (%s)", errno, strerror(errno));
                return -1;
            }
            DEBUG("get session with ID (%s)", pss->session_id);
            struct session_with_mutex *ls = get_ncsession_from_sid(pss->session_id);
            if (ls == NULL) {
                DEBUG("notification: session_id not found (%s)", pss->session_id);
                DEBUG("unlock session lock");
                if (pthread_rwlock_unlock (&session_lock) != 0) {
                    DEBUG("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
                }
                DEBUG("Close notification client");
                return -1;
            }
            DEBUG("lock private lock");
            pthread_mutex_lock(&ls->lock);

            DEBUG("unlock session lock");
            if (pthread_rwlock_unlock (&session_lock) != 0) {
                DEBUG("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
            }

            DEBUG("Found session to subscribe notif.");
            if (ls->closed == 1) {
                DEBUG("session already closed - handle no notification");
                DEBUG("unlock private lock");
                pthread_mutex_unlock(&ls->lock);
                DEBUG("Close notification client");
                return -1;
            }
            if (ls->ntfc_subscribed != 0) {
                DEBUG("notification: already subscribed");
                DEBUG("unlock private lock");
                pthread_mutex_unlock(&ls->lock);
                /* do not close client, only do not subscribe again */
                return 0;
            }
            DEBUG("notification: prepare to subscribe stream");
            DEBUG("unlock session lock");
            pthread_mutex_unlock(&ls->lock);

            /* notif_subscribe locks on its own */
            return notif_subscribe(ls, pss->session_id, (time_t) start, (time_t) stop);
        }
        if (len < 6)
            break;
        break;
    /*
     * this just demonstrates how to use the protocol filter. If you won't
     * study and reject connections based on header content, you don't need
     * to handle this callback
     */

    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
        //dump_handshake_info(wsi);
        /* you could return non-zero here and kill the connection */
        break;
    //gives segfault :-(
    //case LWS_CALLBACK_CLOSED:
    //  if (pss->session_key != NULL) {
    //      free(pss->session_key);
    //  }
    //  if (pss != NULL) {
    //      free(pss);
    //  }

    default:
        break;
    }

    return 0;
}

/* list of supported protocols and callbacks */
static struct lws_protocols protocols[] = {
    /* first protocol must always be HTTP handler */
    {
        "http-only",        /* name */
        callback_http,      /* callback */
        sizeof(struct per_session_data__http), /* per_session_data_size */
        0,                   /* max frame size / rx buffer */
        1,
        NULL
    },
    {
        "notification-protocol",
        callback_notification,
        sizeof(struct per_session_data__notif_client),
        4000,
        2,
        NULL
    },
    { NULL, NULL, 0, 0, 0, NULL } /* terminator */
};

/**
 * initialization of notification module
 */
int notification_init(void)
{
    char cert_path[1024], key_path[1024];
    struct lws_context_creation_info info;
    int debug_level = 7;

    memset(&info, 0, sizeof info);
    info.port = NOTIFICATION_SERVER_PORT;

    /* tell the library what debug level to emit and to send it to syslog */
    lws_set_log_level(debug_level, lwsl_emit_syslog);

    DEBUG("Initialization of libwebsocket");
    max_poll_elements = getdtablesize();
    pollfds = malloc(max_poll_elements * sizeof (struct pollfd));
    fd_lookup = malloc(max_poll_elements * sizeof (int));
    if (pollfds == NULL || fd_lookup == NULL) {
        ERROR("notifications: Out of memory pollfds=%d\n", max_poll_elements);
        return -1;
    }

    info.iface = NULL;
    info.protocols = protocols;

    snprintf(cert_path, sizeof(cert_path), SERVER_CERT_DIR "/" SERVER_CERT);
    snprintf(key_path, sizeof(key_path), SERVER_CERT_DIR "/" SERVER_KEY);

    info.ssl_cert_filepath = cert_path;
    info.ssl_private_key_filepath = key_path;

    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT | LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS;

    /* create server */
    context = lws_create_context(&info);
    if (context == NULL) {
        DEBUG("libwebsocket init failed.");
        return -1;
    }

    if (pthread_key_create(&thread_key, NULL) != 0) {
        ERROR("notifications: pthread_key_create failed");
    }
    return 0;
}

void notification_close(void)
{
    if (context) {
        lws_context_destroy(context);
    }
    free(pollfds);
    free(fd_lookup);

    DEBUG("libwebsockets-test-server exited cleanly\n");
}


/**
 * \brief send notification if any
 * \return < 0 on error
 */
int notification_handle()
{
    static struct timeval tv;
    static unsigned int olds = 0;
    int n = 0;

    gettimeofday(&tv, NULL);

    /*
     * This provokes the LWS_CALLBACK_SERVER_WRITEABLE for every
     * live websocket connection using the DUMB_INCREMENT protocol,
     * as soon as it can take more packets (usually immediately)
     */

    if (((unsigned int)tv.tv_sec - olds) > 0) {
        lws_callback_on_writable_all_protocol(context, &protocols[PROTOCOL_NOTIFICATION]);
        olds = tv.tv_sec;
    }

    /*
     * this represents an existing server's single poll action
     * which also includes libwebsocket sockets
     */

    n = poll(pollfds, count_pollfds, 50);
    if (n < 0) {
        return n;
    }

    if (n) {
        for (n = 0; n < count_pollfds; n++) {
            if (pollfds[n].revents) {
                /*
                 * returns immediately if the fd does not
                 * match anything under libwebsockets
                 * control
                 */
                if (lws_service_fd(context, &pollfds[n]) < 0) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

#endif


#ifndef WITH_NOTIFICATIONS
#ifdef TEST_NOTIFICATION_SERVER
int main(int argc, char **argv)
{
    if (notification_init(NULL, NULL) == -1) {
        fprintf(stderr, "Error during initialization\n");
        return 1;
    }
    while (!force_exit) {
        notification_handle();
    }
    notification_close();
}
#endif
#endif
