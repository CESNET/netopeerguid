/*!
 * \file mod_netconf.c
 * \brief NETCONF Apache modul for Netopeer
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \date 2011
 * \date 2012
 * \date 2013
 */
/*
 * Copyright (C) 2011-2013 CESNET
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
#define _GNU_SOURCE

#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <errno.h>
#include <limits.h>
#include <grp.h>
#include <signal.h>
#include <pthread.h>
#include <ctype.h>

#include <libnetconf.h>
#include <libnetconf_ssh.h>

#include "../config.h"

#ifdef WITH_NOTIFICATIONS
#include "notification_module.h"
#endif

#include "message_type.h"
#include "mod_netconf.h"

#define SCHEMA_DIR "/tmp/yang_models"
#define MAX_PROCS 5
#define SOCKET_FILENAME "/var/run/mod_netconf.sock"
#define MAX_SOCKET_CL 10
#define BUFFER_SIZE 4096
#define ACTIVITY_CHECK_INTERVAL 10  /**< timeout in seconds, how often activity is checked */
#define ACTIVITY_TIMEOUT    (60*60)  /**< timeout in seconds, after this time, session is automaticaly closed. */

/* sleep in master process for non-blocking socket reading, in msec */
#define SLEEP_TIME 200

#ifndef offsetof
#define offsetof(type, member) ((size_t) ((type *) 0)->member)
#endif

/* timeout in msec */
struct timeval timeout = { 1, 0 };

#define NCWITHDEFAULTS  NCWD_MODE_NOTSET

#define MSG_OK 0
#define MSG_OPEN  1
#define MSG_DATA  2
#define MSG_CLOSE 3
#define MSG_ERROR 4
#define MSG_UNKNOWN 5

pthread_rwlock_t session_lock; /**< mutex protecting netconf_sessions_list from multiple access errors */
pthread_mutex_t ntf_history_lock; /**< mutex protecting notification history list */
pthread_mutex_t ntf_hist_clbc_mutex; /**< mutex protecting notification history list */
pthread_mutex_t json_lock; /**< mutex for protecting json-c calls */

unsigned int session_key_generator = 1;
struct session_with_mutex *netconf_sessions_list = NULL;
static const char *sockname;
static pthread_key_t notif_history_key;
pthread_key_t err_reply_key;
volatile int isterminated = 0;
static char* password;

json_object *create_ok_reply(void);
json_object *create_data_reply(const char *data);
static char *netconf_getschema(unsigned int session_key, const char *identifier, const char *version,
                               const char *format, json_object **err);
static void node_add_metadata_recursive(struct lyd_node *data_tree, struct lys_module *module,
                                        json_object *data_json_parent);

static void
signal_handler(int sign)
{
    switch (sign) {
    case SIGINT:
    case SIGTERM:
        isterminated = 1;
        break;
    }
}

int
netconf_callback_ssh_hostkey_check(const char* UNUSED(hostname), ssh_session UNUSED(session))
{
    /* always approve */
    return (EXIT_SUCCESS);
}

char *
netconf_callback_sshauth_passphrase(const char *UNUSED(username), const char *UNUSED(hostname), const char *UNUSED(priv_key_file))
{
    char *buf;
    buf = strdup(password);
    return (buf);
}

char *
netconf_callback_sshauth_password(const char *UNUSED(username), const char *UNUSED(hostname))
{
    char *buf;
    buf = strdup(password);
    return (buf);
}

char *
netconf_callback_sshauth_interactive(const char *UNUSED(name), const char *UNUSED(instruction),
                                     const char *UNUSED(prompt), int UNUSED(echo))
{
    char *buf;
    buf = strdup(password);
    return (buf);
}

void
netconf_callback_error_process(const char *UNUSED(tag),
        const char *UNUSED(type),
        const char *UNUSED(severity),
        const char *UNUSED(apptag),
        const char *UNUSED(path),
        const char *message,
        const char *UNUSED(attribute),
        const char *UNUSED(element),
        const char *UNUSED(ns),
        const char *UNUSED(sid))
{
    json_object **err_reply_p = (json_object **) pthread_getspecific(err_reply_key);
    if (err_reply_p == NULL) {
        ERROR("Error message was not allocated. %s", __func__);
        return;
    }
    json_object *err_reply = *err_reply_p;

    json_object *array = NULL;
    if (err_reply == NULL) {
        ERROR("error calback: empty error list");
        pthread_mutex_lock(&json_lock);
        err_reply = json_object_new_object();
        array = json_object_new_array();
        json_object_object_add(err_reply, "type", json_object_new_int(REPLY_ERROR));
        json_object_object_add(err_reply, "errors", array);
        if (message != NULL) {
            json_object_array_add(array, json_object_new_string(message));
        }
        pthread_mutex_unlock(&json_lock);
        (*err_reply_p) = err_reply;
    } else {
        ERROR("error calback: nonempty error list");
        pthread_mutex_lock(&json_lock);
        if (json_object_object_get_ex(err_reply, "errors", &array) == TRUE) {
            if (message != NULL) {
                json_object_array_add(array, json_object_new_string(message));
            }
        }
        pthread_mutex_unlock(&json_lock);
    }
    pthread_setspecific(err_reply_key, err_reply_p);
    return;
}

/**
 * should be used in locked area
 */
void
prepare_status_message(struct session_with_mutex *s, struct nc_session *session)
{
    json_object *json_obj = NULL;
    json_object *js_tmp = NULL;
    char *old_sid = NULL;
    const char *j_old_sid = NULL;
    const char *cpbltstr;
    struct nc_cpblts* cpblts = NULL;

    if (s == NULL) {
        ERROR("No session given.");
        return;
    }

    pthread_mutex_lock(&json_lock);
    if (s->hello_message != NULL) {
        ERROR("clean previous hello message");
        if (json_object_object_get_ex(s->hello_message, "sid", &js_tmp) == TRUE) {
            j_old_sid = json_object_get_string(js_tmp);
            if (j_old_sid != NULL) {
                old_sid = strdup(j_old_sid);
            }
        }
        json_object_put(s->hello_message);
        s->hello_message = NULL;
    }
    s->hello_message = json_object_new_object();
    if (session != NULL) {
        if (old_sid != NULL) {
            /* use previous sid */
            json_object_object_add(s->hello_message, "sid", json_object_new_string(old_sid));
            free(old_sid);
            old_sid = NULL;
        } else {
            /* we don't have old sid */
            json_object_object_add(s->hello_message, "sid", json_object_new_string(nc_session_get_id(session)));
        }
        json_object_object_add(s->hello_message, "version", json_object_new_string((nc_session_get_version(session) == 0)?"1.0":"1.1"));
        json_object_object_add(s->hello_message, "host", json_object_new_string(nc_session_get_host(session)));
        json_object_object_add(s->hello_message, "port", json_object_new_string(nc_session_get_port(session)));
        json_object_object_add(s->hello_message, "user", json_object_new_string(nc_session_get_user(session)));
        cpblts = nc_session_get_cpblts (session);
        if (cpblts != NULL) {
            json_obj = json_object_new_array();
            nc_cpblts_iter_start (cpblts);
            while ((cpbltstr = nc_cpblts_iter_next (cpblts)) != NULL) {
                json_object_array_add(json_obj, json_object_new_string(cpbltstr));
            }
            json_object_object_add(s->hello_message, "capabilities", json_obj);
        }
        DEBUG("%s", json_object_to_json_string(s->hello_message));
    } else {
        ERROR("Session was not given.");
        json_object_object_add(s->hello_message, "type", json_object_new_int(REPLY_ERROR));
        json_object_object_add(s->hello_message, "error-message", json_object_new_string("Invalid session identifier."));
    }
    DEBUG("Status info from hello message prepared");
    pthread_mutex_unlock(&json_lock);

}

void
create_err_reply_p()
{
    json_object **err_reply = calloc(1, sizeof(json_object **));
    if (err_reply == NULL) {
        ERROR("Allocation of err_reply storage failed!");
        return;
    }
    if (pthread_setspecific(err_reply_key, err_reply) != 0) {
        ERROR("cannot set thread-specific value.");
    }
}

void
clean_err_reply()
{
    json_object **err_reply = (json_object **) pthread_getspecific(err_reply_key);
    if (err_reply != NULL) {
        if (*err_reply != NULL) {
            pthread_mutex_lock(&json_lock);
            json_object_put(*err_reply);
            pthread_mutex_unlock(&json_lock);
        }
        if (pthread_setspecific(err_reply_key, err_reply) != 0) {
            ERROR("Cannot set thread-specific hash value.");
        }
    }
}

void
free_err_reply()
{
    json_object **err_reply = (json_object **) pthread_getspecific(err_reply_key);
    if (err_reply != NULL) {
        if (*err_reply != NULL) {
            pthread_mutex_lock(&json_lock);
            json_object_put(*err_reply);
            pthread_mutex_unlock(&json_lock);
        }
        free(err_reply);
        err_reply = NULL;
        if (pthread_setspecific(err_reply_key, err_reply) != 0) {
            ERROR("Cannot set thread-specific hash value.");
        }
    }
}

static struct session_with_mutex *
session_get_locked(unsigned int session_key, json_object **err)
{
    struct session_with_mutex *locked_session;

    /* get non-exclusive (read) access to sessions_list (conns) */
    DEBUG("LOCK wrlock %s", __func__);
    if (pthread_rwlock_rdlock(&session_lock) != 0) {
        if (*err) {
            *err = create_error_reply("Locking failed.");
        }
        return NULL;
    }
    /* get session where send the RPC */
    for (locked_session = netconf_sessions_list;
         locked_session && (locked_session->session_key != session_key);
         locked_session = locked_session->next);
    if (!locked_session) {
        if (*err) {
            *err = create_error_reply("Session not found.");
        }
        return NULL;
    }

    /* get exclusive access to session */
    DEBUG("LOCK mutex %s", __func__);
    if (pthread_mutex_lock(&locked_session->lock) != 0) {
        if (*err) {
            *err = create_error_reply("Locking failed.");
        }
        goto wrlock_fail;
    }
    return locked_session;

wrlock_fail:
    DEBUG("UNLOCK wrlock %s", __func__);
    pthread_rwlock_unlock(&session_lock);
    return NULL;
}

static void
session_unlock(struct session_with_mutex *locked_session)
{
    DEBUG("UNLOCK mutex %s", __func__);
    pthread_mutex_unlock(&locked_session->lock);
    DEBUG("UNLOCK wrlock %s", __func__);
    pthread_rwlock_unlock(&session_lock);
}

/**
 * \defgroup netconf_operations NETCONF operations
 * The list of NETCONF operations that mod_netconf supports.
 * @{
 */

/**
 * \brief Send RPC and wait for reply with timeout.
 *
 * \param[in] session libnetconf session
 * \param[in] rpc     prepared RPC message
 * \param[in] timeout timeout in miliseconds, -1 for blocking, 0 for non-blocking
 * \param[out] reply  reply from the server
 * \return Value from nc_session_recv_reply() or NC_MSG_UNKNOWN when send_rpc() fails.
 * On success, it returns NC_MSG_REPLY.
 */
NC_MSG_TYPE
netconf_send_recv_timed(struct nc_session *session, nc_rpc *rpc, int timeout, nc_reply **reply)
{
    const nc_msgid msgid = NULL;
    NC_MSG_TYPE ret = NC_MSG_UNKNOWN;
    msgid = nc_session_send_rpc(session, rpc);
    if (msgid == NULL) {
        return ret;
    }
    do {
        ret = nc_session_recv_reply(session, timeout, reply);
        if (ret == NC_MSG_HELLO) {
            ERROR("<hello> received instead reply, it will be lost.");
            nc_reply_free(*reply);
        }
        if (ret == NC_MSG_WOULDBLOCK) {
            ERROR("Timeout for receiving RPC reply expired.");
            break;
        }
    } while (ret == NC_MSG_HELLO || ret == NC_MSG_NOTIFICATION);
    return ret;
}

static int
ctx_download_module(struct session_with_mutex *session, const char *model_name, const char *revision, const char *schema_dir)
{
    json_object *err = NULL;
    char *model_data = NULL, *model_path;
    size_t length;
    FILE *file;

    DEBUG("UNLOCK rwlock %s", __func__);
    if (pthread_rwlock_unlock(&session_lock) != 0) {
        ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        return 1;
    }

    model_data = netconf_getschema(session->session_key, model_name, revision, "yin", &err);

    DEBUG("LOCK rwlock %s", __func__);
    if (pthread_rwlock_wrlock(&session_lock) != 0) {
        ERROR("Error while locking rwlock: %d (%s)", errno, strerror(errno));
        return 1;
    }

    if (!model_data) {
        if (err) {
            json_object_put(err);
        }
        ERROR("Failed to get-schema of \"%s\".", model_name);
        return 1;
    }

    if (revision) {
        asprintf(&model_path, "%s/%s@%s.yin", schema_dir, model_name, revision);
    } else {
        asprintf(&model_path, "%s/%s.yin", schema_dir, model_name);
    }

    file = fopen(model_path, "w");
    if (!file) {
        ERROR("Failed to open \"%s\" for writing (%s).", model_path, strerror(errno));
        free(model_data);
        free(model_path);
        return 1;
    }
    free(model_path);

    length = strlen(model_data);
    if (fwrite(model_data, 1, length, file) < length) {
        ERROR("Failed to store the model \"%s\".", model_name);
        free(model_data);
        fclose(file);
        return 1;
    }

    free(model_data);
    fclose(file);
    return 0;
}

static void
ctx_enable_features(struct lys_module *module, const char *cpblt)
{
    char *ptr, *ptr2, *features = NULL;

    /* parse features */
    ptr = strstr(cpblt, "features=");
    if (ptr) {
        ptr += 9;
        ptr2 = strchr(ptr, '&');
        if (!ptr2) {
            ptr2 = ptr + strlen(ptr);
        }
        features = strndup(ptr, ptr2 - ptr);
    }

    /* enable features */
    if (features) {
        /* basically manual strtok_r (to avoid macro) */
        ptr2 = features;
        for (ptr = features; *ptr; ++ptr) {
            if (*ptr == ',') {
                *ptr = '\0';
                /* remember last feature */
                ptr2 = ptr + 1;
            }
        }

        ptr = features;
        lys_features_enable(module, ptr);
        while (ptr != ptr2) {
            ptr += strlen(ptr) + 1;
            lys_features_enable(module, ptr);
        }

        free(features);
    }
}

static void
ctx_enable_capabs(struct lys_module *ietfnc, json_object *cpb_array)
{
    json_object *item;
    int i;
    const char *capab;

    /* set supported capabilities from ietf-netconf */
    for (i = 0; i < json_object_array_length(cpb_array); ++i) {
        item = json_object_array_get_idx(cpb_array, i);
        capab = json_object_get_string(item);

        if (!strncmp(capab, "urn:ietf:params:netconf:capability:", 35)) {
            if (!strncmp(capab, "writable-running", 16)) {
                lys_features_enable(ietfnc, "writable-running");
            } else if (!strncmp(capab, "candidate", 9)) {
                lys_features_enable(ietfnc, "candidate");
            } else if (!strcmp(capab, "confirmed-commit:1.1")) {
                lys_features_enable(ietfnc, "confirmed-commit");
            } else if (!strncmp(capab, "rollback-on-error", 17)) {
                lys_features_enable(ietfnc, "rollback-on-error");
            } else if (!strcmp(capab, "validate:1.1")) {
                lys_features_enable(ietfnc, "validate");
            } else if (!strncmp(capab, "startup", 7)) {
                lys_features_enable(ietfnc, "startup");
            } else if (!strncmp(capab, "url", 3)) {
                lys_features_enable(ietfnc, "url");
            } else if (!strncmp(capab, "xpath", 5)) {
                lys_features_enable(ietfnc, "xpath");
            }
        }
    }
}

static int
prepare_context(struct session_with_mutex *session)
{
    struct lys_module *module;
    json_object *array, *item;
    char *ptr, *ptr2;
    char *model_name = NULL, *revision = NULL;
    const char *capab;
    int i, get_schema_support;

    if (json_object_object_get_ex(session->hello_message, "capabilities", &array) == FALSE) {
        return 1;
    }

    get_schema_support = 0;
    for (i = 0; i < json_object_array_length(array); ++i) {
        item = json_object_array_get_idx(array, i);
        capab = json_object_get_string(item);

        if (!strncmp(capab, "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring", 51)) {
            get_schema_support = 1;
            break;
        }
    }

    if (get_schema_support) {
        errno = 0;
        if (eaccess(SCHEMA_DIR, W_OK)) {
            if (errno == ENOENT) {
                if (mkdir(SCHEMA_DIR, 00755)) {
                    ERROR("Failed to create temp model dir \"%s\" (%s).", SCHEMA_DIR, strerror(errno));
                    return 1;
                }
            } else {
                ERROR("Unable to write to temp model dir \"%s\" (%s).", SCHEMA_DIR, strerror(errno));
                return 1;
            }
        }

        session->ctx = ly_ctx_new(SCHEMA_DIR);
    } else {
        /* TODO */
        session->ctx = ly_ctx_new(NULL);
    }

loop:
    /* download all the models first or load them directly */
    for (i = 0; i < json_object_array_length(array); ++i) {
        item = json_object_array_get_idx(array, i);
        capab = json_object_get_string(item);
        if (!strncmp(capab, "urn:ietf:params:netconf:capability", 34)
                || !strncmp(capab, "urn:ietf:params:netconf:base", 28)) {
            continue;
        }

        /* get module */
        ptr = strstr(capab, "module=");
        if (!ptr) {
        ERROR("Unknown capability \"%s\" could not be parsed.", capab);
            continue;
        }
        ptr += 7;
        ptr2 = strchr(ptr, '&');
        if (!ptr2) {
            ptr2 = ptr + strlen(ptr);
        }
        model_name = strndup(ptr, ptr2 - ptr);

        /* get revision */
        ptr = strstr(capab, "revision=");
        if (ptr) {
            ptr += 9;
            ptr2 = strchr(ptr, '&');
            if (!ptr2) {
                ptr2 = ptr + strlen(ptr);
            }
            revision = strndup(ptr, ptr2 - ptr);
        }

        if (get_schema_support) {
            ctx_download_module(session, model_name, revision, SCHEMA_DIR);
        } else {
            module = ly_ctx_get_module(session->ctx, model_name, revision);
            if (!module) {
                module = ly_ctx_load_module(session->ctx, NULL, model_name, revision);
                if (module) {
                    if (!strcmp(module->name, "ietf-netconf")) {
                        ctx_enable_capabs(module, array);
                    } else {
                        ctx_enable_features(module, capab);
                    }
                }
            }
        }

        free(model_name);
        free(revision);
        revision = NULL;
    }

    if (get_schema_support) {
        /* we have downloaded all the models, load them now */
        get_schema_support = 0;
        goto loop;
    }

    return 0;
}

/**
 * \brief Connect to NETCONF server
 *
 * \warning Session_key hash is not bound with caller identification. This could be potential security risk.
 */
static unsigned int
netconf_connect(const char *host, const char *port, const char *user, const char *pass, struct nc_cpblts *cpblts)
{
    struct nc_session* session = NULL;
    struct session_with_mutex *locked_session, *last_session;

    /* connect to the requested NETCONF server */
    password = (char*)pass;
    DEBUG("prepare to connect %s@%s:%s", user, host, port);
    session = nc_session_connect(host, (unsigned short) atoi (port), user, cpblts);
    DEBUG("nc_session_connect done");

    /* if connected successful, add session to the list */
    if (session != NULL) {
        if ((locked_session = calloc(1, sizeof(struct session_with_mutex))) == NULL || pthread_mutex_init (&locked_session->lock, NULL) != 0) {
            nc_session_free(session);
            session = NULL;
            free(locked_session);
            locked_session = NULL;
            ERROR("Creating structure session_with_mutex failed %d (%s)", errno, strerror(errno));
            return 0;
        }
        locked_session->session = session;
        locked_session->last_activity = time(NULL);
        locked_session->hello_message = NULL;
        locked_session->closed = 0;
        pthread_mutex_init(&locked_session->lock, NULL);
        DEBUG("Before session_lock");
        /* get exclusive access to sessions_list (conns) */
        DEBUG("LOCK wrlock %s", __func__);
        if (pthread_rwlock_wrlock(&session_lock) != 0) {
            nc_session_free(session);
            free(locked_session);
            ERROR("Error while locking rwlock: %d (%s)", errno, strerror(errno));
            return 0;
        }
        locked_session->ntfc_subscribed = 0;
        DEBUG("Add connection to the list");
        if (!netconf_sessions_list) {
            netconf_sessions_list = locked_session;
        } else {
            for (last_session = netconf_sessions_list; last_session->next; last_session = last_session->next);
            last_session->next = locked_session;
            locked_session->prev = last_session;
        }
        DEBUG("Before session_unlock");

        /* no need to lock session, noone can read it while we have wrlock */

        /* store information about session from hello message for future usage */
        prepare_status_message(locked_session, session);

        /* create context from the hello message cpabilities */
        if (prepare_context(locked_session)) {
            nc_session_free(session);
            free(locked_session);
            DEBUG("UNLOCK wrlock %s", __func__);
            pthread_rwlock_unlock(&session_lock);
            ERROR("Failed to prepare context");
            return 0;
        }

        DEBUG("NETCONF session established");
        locked_session->session_key = session_key_generator;
        ++session_key_generator;
        if (session_key_generator == UINT_MAX) {
            session_key_generator = 1;
        }

        /* unlock session list */
        DEBUG("UNLOCK wrlock %s", __func__);
        if (pthread_rwlock_unlock(&session_lock) != 0) {
            ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        }

        return locked_session->session_key;
    }

    ERROR("Connection could not be established");
    return 0;
}

static int
close_and_free_session(struct session_with_mutex *locked_session)
{
    DEBUG("lock private lock.");
    DEBUG("LOCK mutex %s", __func__);
    if (pthread_mutex_lock(&locked_session->lock) != 0) {
        ERROR("Error while locking rwlock");
    }
    locked_session->ntfc_subscribed = 0;
    locked_session->closed = 1;
    if (locked_session->session != NULL) {
        nc_session_free(locked_session->session);
        locked_session->session = NULL;
    }
    DEBUG("session closed.");
    DEBUG("unlock private lock.");
    DEBUG("UNLOCK mutex %s", __func__);
    if (pthread_mutex_unlock(&locked_session->lock) != 0) {
        ERROR("Error while locking rwlock");
    }

    DEBUG("unlock session lock.");
    DEBUG("closed session, disabled notif(?), wait 0.5s");
    usleep(500000); /* let notification thread stop */

    /* session shouldn't be used by now */
    /** \todo free all notifications from queue */
    free(locked_session->notifications);
    pthread_mutex_destroy(&locked_session->lock);
    if (locked_session->hello_message != NULL) {
        json_object_put(locked_session->hello_message);
        locked_session->hello_message = NULL;
    }
    locked_session->session = NULL;
    ly_ctx_destroy(locked_session->ctx);
    free(locked_session);
    locked_session = NULL;
    DEBUG("NETCONF session closed, everything cleared.");
    return (EXIT_SUCCESS);
}

static int
netconf_close(unsigned int session_key, json_object **reply)
{
    struct session_with_mutex *locked_session;

    DEBUG("Session to close: %u", session_key);

    /* get exclusive (write) access to sessions_list (conns) */
    DEBUG("lock session lock.");
    DEBUG("LOCK wrlock %s", __func__);
    if (pthread_rwlock_wrlock (&session_lock) != 0) {
        ERROR("Error while locking rwlock");
        (*reply) = create_error_reply("Internal: Error while locking.");
        return EXIT_FAILURE;
    }
    /* remove session from the active sessions list -> nobody new can now work with session */
    for (locked_session = netconf_sessions_list;
         locked_session && (locked_session->session_key != session_key);
         locked_session = locked_session->next);

    if (!locked_session) {
        ERROR("Could not find the session %u to close.", session_key);
        (*reply) = create_error_reply("Internal: Error while finding a session.");
        return EXIT_FAILURE;
    }

    if (!locked_session->prev) {
        netconf_sessions_list = netconf_sessions_list->next;
        netconf_sessions_list->prev = NULL;
    } else {
        locked_session->prev->next = locked_session->next;
        if (locked_session->next) {
            locked_session->next->prev = locked_session->prev;
        }
    }

    DEBUG("UNLOCK wrlock %s", __func__);
    if (pthread_rwlock_unlock (&session_lock) != 0) {
        ERROR("Error while unlocking rwlock");
        (*reply) = create_error_reply("Internal: Error while unlocking.");
    }

    if ((locked_session != NULL) && (locked_session->session != NULL)) {
        return close_and_free_session(locked_session);
    } else {
        ERROR("Unknown session to close");
        (*reply) = create_error_reply("Internal: Unkown session to close.");
        return (EXIT_FAILURE);
    }
    (*reply) = NULL;
}

/**
 * Test reply message type and return error message.
 *
 * \param[in] session   nc_session internal struct
 * \param[in] session_key session ID, 0 to disable disconnect on error
 * \param[in] msgt  RPC-REPLY message type
 * \param[out] data
 * \return NULL on success
 */
json_object *
netconf_test_reply(struct nc_session *session, unsigned int session_key, NC_MSG_TYPE msgt, nc_reply *reply, char **data)
{
    NC_REPLY_TYPE replyt;
    json_object *err = NULL;

    /* process the result of the operation */
    switch (msgt) {
        case NC_MSG_UNKNOWN:
            if (nc_session_get_status(session) != NC_SESSION_STATUS_WORKING) {
                ERROR("mod_netconf: receiving rpc-reply failed");
                if (session_key) {
                    netconf_close(session_key, &err);
                }
                if (err != NULL) {
                    return err;
                }
                return create_error_reply("Internal: Receiving RPC-REPLY failed.");
            }
        case NC_MSG_NONE:
            /* there is error handled by callback */
            if (data != NULL) {
                free(*data);
                (*data) = NULL;
            }
            return NULL;
        case NC_MSG_REPLY:
            switch (replyt = nc_reply_get_type(reply)) {
                case NC_REPLY_OK:
                    if ((data != NULL) && (*data != NULL)) {
                        free(*data);
                        (*data) = NULL;
                    }
                    return create_ok_reply();
                case NC_REPLY_DATA:
                    if (((*data) = nc_reply_get_data(reply)) == NULL) {
                        ERROR("mod_netconf: no data from reply");
                        return create_error_reply("Internal: No data from reply received.");
                    } else {
                        return NULL;
                    }
                    break;
                case NC_REPLY_ERROR:
                    ERROR("mod_netconf: unexpected rpc-reply (%d)", replyt);
                    if (data != NULL) {
                        free(*data);
                        (*data) = NULL;
                    }
                    return create_error_reply(nc_reply_get_errormsg(reply));
                default:
                    ERROR("mod_netconf: unexpected rpc-reply (%d)", replyt);
                    if (data != NULL) {
                        free(*data);
                        (*data) = NULL;
                    }
                    return create_error_reply("Unknown type of NETCONF reply.");
            }
            break;
        default:
            ERROR("mod_netconf: unexpected reply message received (%d)", msgt);
            if (data != NULL) {
                free(*data);
                (*data) = NULL;
            }
            return create_error_reply("Internal: Unexpected RPC-REPLY message type.");
    }
}

json_object *
netconf_unlocked_op(struct nc_session *session, nc_rpc *rpc)
{
    nc_reply* reply = NULL;
    NC_MSG_TYPE msgt;

    /* check requests */
    if (rpc == NULL) {
        ERROR("mod_netconf: rpc is not created");
        return create_error_reply("Internal error: RPC is not created");
    }

    if (session != NULL) {
        /* send the request and get the reply */
        msgt = netconf_send_recv_timed(session, rpc, 50000, &reply);
        /* process the result of the operation */
        return netconf_test_reply(session, 0, msgt, reply, NULL);
    } else {
        ERROR("Unknown session to process.");
        return create_error_reply("Internal error: Unknown session to process.");
    }
}

/**
 * Perform RPC method that returns data.
 *
 * \param[in] session_id    session identifier
 * \param[in] rpc   RPC message to perform
 * \param[out] received_data    received data string, can be NULL when no data expected, value can be set to NULL if no data received
 * \return NULL on success, json object with error otherwise
 */
static json_object *
netconf_op(unsigned int session_key, nc_rpc *rpc, char **received_data)
{
    struct session_with_mutex * locked_session;
    nc_reply* reply = NULL;
    json_object *res = NULL;
    char *data = NULL;
    NC_MSG_TYPE msgt;

    /* check requests */
    if (rpc == NULL) {
        ERROR("mod_netconf: rpc is not created");
        res = create_error_reply("Internal: RPC could not be created.");
        data = NULL;
        goto finished;
    }

    locked_session = session_get_locked(session_key, &res);
    if (!locked_session) {
        ERROR("Unknown session or locking failed.");
        goto finished;
    }

    locked_session->last_activity = time(NULL);

    /* send the request and get the reply */
    msgt = netconf_send_recv_timed(locked_session->session, rpc, 2000000, &reply);

    session_unlock(locked_session);

    res = netconf_test_reply(locked_session->session, session_key, msgt, reply, &data);

finished:
    nc_reply_free(reply);
    if (received_data != NULL) {
        (*received_data) = data;
    } else {
        if (data != NULL) {
            free(data);
            data = NULL;
        }
    }
    return res;
}

static char *
netconf_getconfig(unsigned int session_key, NC_DATASTORE source, const char *filter, int strict, json_object **err)
{
    nc_rpc* rpc;
    struct nc_filter *f = NULL;
    struct session_with_mutex *locked_session;
    char* data = NULL, *data_xml;
    json_object *res = NULL, *data_cjson;
    enum json_tokener_error tok_err;
    struct lyd_node *node, *sibling, *next;

    /* create filter if set */
    if (filter != NULL) {
        f = nc_filter_new(NC_FILTER_SUBTREE, filter);
    }

    /* create requests */
    rpc = nc_rpc_getconfig(source, f);
    nc_filter_free(f);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return (NULL);
    }

    /* tell server to show all elements even if they have default values */
#ifdef HAVE_WITHDEFAULTS_TAGGED
    if (nc_rpc_capability_attr(rpc, NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_ALL_TAGGED))
#else
    if (nc_rpc_capability_attr(rpc, NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_NOTSET))
    //if (nc_rpc_capability_attr(rpc, NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_ALL))
#endif
    {
        ERROR("mod_netconf: setting withdefaults failed");
    }

    res = netconf_op(session_key, rpc, &data);
    nc_rpc_free(rpc);
    if (res != NULL) {
        (*err) = res;
    } else {
        (*err) = NULL;
    }

    if (data) {
        for (locked_session = netconf_sessions_list;
             locked_session && (locked_session->session_key != session_key);
             locked_session = locked_session->next);
        /* won't fail */

        asprintf(&data_xml, "<get-config>%s</get-config>", data);
        node = lyd_parse(locked_session->ctx, data_xml, LYD_XML, LYD_OPT_GETCONFIG | (strict ? LYD_OPT_STRICT : 0));
        free(data_xml);
        free(data);
        if (!node) {
            ERROR("Parsing <get-config> data failed.");
            return NULL;
        }

        /* replace XML data with JSON data */
        if (lyd_print_mem(&data, node, LYD_JSON)) {
            ERROR("Printing JSON <get-config> data failed.");
            LY_TREE_FOR(node, sibling) {
                lyd_free(sibling);
            }
            return NULL;
        }

        /* parse JSON data into cjson */
        pthread_mutex_lock(&json_lock);
        data_cjson = json_tokener_parse_verbose(data, &tok_err);
        if (!data_cjson) {
            ERROR("Parsing JSON config failed (%s).", json_tokener_error_desc(tok_err));
            pthread_mutex_unlock(&json_lock);
            LY_TREE_FOR(node, sibling) {
                lyd_free(sibling);
            }
            free(data);
            return NULL;
        }
        free(data);

        /* go simultaneously through both trees and add metadata */
        LY_TREE_FOR_SAFE(node, next, sibling) {
            node_add_metadata_recursive(sibling, NULL, data_cjson);
            lyd_free(sibling);
        }

        data = strdup(json_object_to_json_string_ext(data_cjson, 0));
        json_object_put(data_cjson);
        pthread_mutex_unlock(&json_lock);
    }

    return (data);
}

static char *
netconf_getschema(unsigned int session_key, const char *identifier, const char *version, const char *format, json_object **err)
{
    nc_rpc* rpc;
    char* data = NULL;
    json_object *res = NULL;

    /* create requests */
    rpc = nc_rpc_getschema(identifier, version, format);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return (NULL);
    }

    res = netconf_op(session_key, rpc, &data);
    nc_rpc_free (rpc);
    if (res != NULL) {
        (*err) = res;
    } else {
        (*err) = NULL;
    }

    return (data);
}

static char *
netconf_get(unsigned int session_key, const char* filter, int strict, json_object **err)
{
    nc_rpc* rpc;
    struct nc_filter *f = NULL;
    char* data = NULL, *data_xml;
    json_object *res = NULL, *data_cjson;
    enum json_tokener_error tok_err;
    struct session_with_mutex *locked_session;
    struct lyd_node *node, *sibling, *next;

    /* create filter if set */
    if (filter != NULL) {
        f = nc_filter_new(NC_FILTER_SUBTREE, filter);
    }

    /* create requests */
    rpc = nc_rpc_get(f);
    nc_filter_free(f);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return (NULL);
    }

    /* tell server to show all elements even if they have default values */
    if (nc_rpc_capability_attr(rpc, NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_NOTSET)) {
    //if (nc_rpc_capability_attr(rpc, NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_ALL)) {
    //if (nc_rpc_capability_attr(rpc, NC_CAP_ATTR_WITHDEFAULTS_MODE, NCWD_MODE_ALL_TAGGED)) {
        ERROR("mod_netconf: setting withdefaults failed");
    }

    res = netconf_op(session_key, rpc, &data);
    nc_rpc_free(rpc);
    if (res != NULL) {
        (*err) = res;
    } else {
        (*err) = NULL;
    }

    if (data) {
        for (locked_session = netconf_sessions_list;
             locked_session && (locked_session->session_key != session_key);
             locked_session = locked_session->next);
        /* won't fail */

        asprintf(&data_xml, "<get>%s</get>", data);
        node = lyd_parse(locked_session->ctx, data_xml, LYD_XML, LYD_OPT_GET | (strict ? LYD_OPT_STRICT : 0));
        free(data_xml);
        free(data);
        if (!node) {
            ERROR("Parsing <get> data failed.");
            return NULL;
        }

        /* replace XML data with JSON data */
        if (lyd_print_mem(&data, node, LYD_JSON)) {
            ERROR("Printing JSON <get> data failed.");
            LY_TREE_FOR(node, sibling) {
                lyd_free(sibling);
            }
            return NULL;
        }

        /* parse JSON data into cjson */
        pthread_mutex_lock(&json_lock);
        data_cjson = json_tokener_parse_verbose(data, &tok_err);
        if (!data_cjson) {
            ERROR("Parsing JSON config failed (%s).", json_tokener_error_desc(tok_err));
            pthread_mutex_unlock(&json_lock);
            LY_TREE_FOR(node, sibling) {
                lyd_free(sibling);
            }
            free(data);
            return NULL;
        }
        free(data);

        /* go simultaneously through both trees and add metadata */
        LY_TREE_FOR_SAFE(node, next, sibling) {
            node_add_metadata_recursive(sibling, NULL, data_cjson);
            lyd_free(sibling);
        }

        data = strdup(json_object_to_json_string_ext(data_cjson, 0));
        json_object_put(data_cjson);
        pthread_mutex_unlock(&json_lock);
    }

    return data;
}

static json_object *
netconf_copyconfig(unsigned int session_key, NC_DATASTORE source, NC_DATASTORE target, const char *config,
                   const char *uri_src, const char *uri_trg)
{
    nc_rpc* rpc;
    json_object *res = NULL;

    /* create requests */
    if (source == NC_DATASTORE_CONFIG) {
        if (target == NC_DATASTORE_URL) {
            /* config, url */
            rpc = nc_rpc_copyconfig(source, target, config, uri_trg);
        } else {
            /* config, datastore */
            rpc = nc_rpc_copyconfig(source, target, config);
        }
    } else if (source == NC_DATASTORE_URL) {
        if (target == NC_DATASTORE_URL) {
            /* url, url */
            rpc = nc_rpc_copyconfig(source, target, uri_src, uri_trg);
        } else {
            /* url, datastore */
            rpc = nc_rpc_copyconfig(source, target, uri_src);
        }
    } else {
        if (target == NC_DATASTORE_URL) {
            /* datastore, url */
            rpc = nc_rpc_copyconfig(source, target, uri_trg);
        } else {
            /* datastore, datastore */
            rpc = nc_rpc_copyconfig(source, target);
        }
    }
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, NULL);
    nc_rpc_free(rpc);

    return res;
}

static json_object *
netconf_editconfig(unsigned int session_key, NC_DATASTORE source, NC_DATASTORE target, NC_EDIT_DEFOP_TYPE defop,
                   NC_EDIT_ERROPT_TYPE erropt, NC_EDIT_TESTOPT_TYPE testopt, const char *config_or_url)
{
    nc_rpc* rpc;
    json_object *res = NULL;

    /* create requests */
    rpc = nc_rpc_editconfig(target, source, defop, erropt, testopt, config_or_url);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, NULL);
    nc_rpc_free (rpc);

    return res;
}

static json_object *
netconf_killsession(unsigned int session_key, const char *sid)
{
    nc_rpc *rpc;
    json_object *res = NULL;

    /* create requests */
    rpc = nc_rpc_killsession(sid);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, NULL);
    nc_rpc_free(rpc);
    return res;
}

static json_object *
netconf_onlytargetop(unsigned int session_key, NC_DATASTORE target, nc_rpc *(*op_func)(NC_DATASTORE))
{
    nc_rpc* rpc;
    json_object *res = NULL;

    /* create requests */
    rpc = op_func(target);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, NULL);
    nc_rpc_free (rpc);
    return res;
}

static json_object *
netconf_deleteconfig(unsigned int session_key, NC_DATASTORE target, const char *url)
{
    nc_rpc *rpc = NULL;
    json_object *res = NULL;
    if (target != NC_DATASTORE_URL) {
        rpc = nc_rpc_deleteconfig(target);
    } else {
        rpc = nc_rpc_deleteconfig(target, url);
    }
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, NULL);
    nc_rpc_free (rpc);
    return res;
}

static json_object *
netconf_lock(unsigned int session_key, NC_DATASTORE target)
{
    return (netconf_onlytargetop(session_key, target, nc_rpc_lock));
}

static json_object *
netconf_unlock(unsigned int session_key, NC_DATASTORE target)
{
    return (netconf_onlytargetop(session_key, target, nc_rpc_unlock));
}

static json_object *
netconf_generic(unsigned int session_key, const char *content, char **data)
{
    nc_rpc* rpc = NULL;
    json_object *res = NULL;

    /* create requests */
    rpc = nc_rpc_generic(content);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    if (data != NULL) {
        // TODO ?free(*data);
        (*data) = NULL;
    }

    /* get session where send the RPC */
    res = netconf_op(session_key, rpc, data);
    nc_rpc_free (rpc);
    return res;
}

static void
node_metadata_children(struct lys_node *node, json_object *parent)
{
    json_object *array, *array_item;
    struct lys_node *child;

    array = json_object_new_array();

    LY_TREE_FOR(node->child, child) {
        array_item = json_object_new_string(child->name);
        json_object_array_add(array, array_item);
    }

    json_object_object_add(parent, "children", array);
}

static void
node_metadata_container(struct lys_node_container *cont, json_object *parent)
{
    json_object *obj;

    /* element type */
    obj = json_object_new_string("container");
    json_object_object_add(parent, "eltype", obj);

    /* config */
    if (cont->flags & LYS_CONFIG_R) {
        obj = json_object_new_boolean(0);
    } else {
        obj = json_object_new_boolean(1);
    }
    json_object_object_add(parent, "config", obj);

    /* TODO */
    /* description */

    /* if-feature */

    /* must */

    /* presence */

    /* reference */

    /* status */

    /* typedef */

    /* when */

    /* children */
    node_metadata_children((struct lys_node *)cont, parent);
}

static int
node_add_metadata(struct lys_node *node, struct lys_module *module, json_object *parent)
{
    struct lys_module *cur_module;
    json_object *meta_obj;
    char *obj_name;

    cur_module = node->module;
    if (cur_module->type) {
        cur_module = ((struct lys_submodule *)cur_module)->belongsto;
    }
    if (cur_module == module) {
        asprintf(&obj_name, "$@%s", node->name);
    } else {
        asprintf(&obj_name, "$@%s:%s", cur_module->name, node->name);
    }

    /* in (leaf-)lists the metadata could have already been added */
    if (json_object_object_get_ex(parent, obj_name, NULL) == TRUE) {
        free(obj_name);
        return 1;
    }

    meta_obj = json_object_new_object();

    switch (node->nodetype) {
        case LYS_CONTAINER:
            node_metadata_container((struct lys_node_container *)node, meta_obj);
            break;
        /* TODO LYS_AUGMENT
        LYS_CHOICE
        LYS_LEAF
        LYS_LEAFLIST
        LYS_LIST
        LYS_ANYXML
        LYS_GROUPING
        LYS_CASE
        LYS_INPUT
        LYS_OUTPUT
        LYS_NOTIF
        LYS_RPC
        LYS_USES*/
    }

    /* just a precaution */
    if (json_object_get_type(parent) != json_type_object) {
        ERROR("Internal: wrong JSON type (%s:%d)", __FILE__, __LINE__);
        free(obj_name);
        return 1;
    }

    json_object_object_add(parent, obj_name, meta_obj);
    free(obj_name);
    return 0;
}

static void
node_add_metadata_recursive(struct lyd_node *data_tree, struct lys_module *module, json_object *data_json_parent)
{
    struct lys_module *cur_module;
    struct lys_node *list_schema;
    struct lyd_node *child, *list_item;
    json_object *child_json, *list_child_json;
    char *child_name;
    int list_idx;

    /* add data_tree metadata */
    if (node_add_metadata(data_tree->schema, module, data_json_parent)) {
        return;
    }

    /* get data_tree module */
    cur_module = data_tree->schema->module;
    if (cur_module->type) {
        cur_module = ((struct lys_submodule *)cur_module)->belongsto;
    }

    if (!(data_tree->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML))) {
        /* print correct data_tree JSON name */
        if (cur_module == module) {
            asprintf(&child_name, "%s", data_tree->schema->name);
        } else {
            asprintf(&child_name, "%s:%s", cur_module->name, data_tree->schema->name);
        }

        /* go down in JSON object */
        if (json_object_object_get_ex(data_json_parent, child_name, &child_json) == FALSE) {
            ERROR("Internal: failed to get JSON object \"%s\".", child_name);
            free(child_name);
            return;
        }
        free(child_name);

        if (data_tree->schema->nodetype == LYS_LIST) {
            if (json_object_get_type(child_json) != json_type_array) {
                ERROR("Internal: type mismatch (%s:%d)", __FILE__, __LINE__);
                return;
            }
            /* go down in data tree for every item, we process them all now, skip later
             * (metadata duplicate will be detected at the beginning of this function) */
            list_idx = 0;
            list_schema = data_tree->schema;

            LY_TREE_FOR(data_tree, list_item) {
                /* another list member */
                if (list_item->schema == list_schema) {
                    list_child_json = json_object_array_get_idx(child_json, list_idx);
                    if (!list_child_json) {
                        ERROR("Internal: list \"%s\" idx out-of-bounds", list_schema->name);
                        return;
                    }
                    LY_TREE_FOR(list_item->child, child) {
                        node_add_metadata_recursive(child, cur_module, list_child_json);
                    }

                    ++list_idx;
                }
            }
        } else {
            if (json_object_get_type(child_json) != json_type_object) {
                ERROR("Internal: type mismatch (%s:%d)", __FILE__, __LINE__);
                return;
            }
            /* go down in data tree */
            LY_TREE_FOR(data_tree->child, child) {
                node_add_metadata_recursive(child, cur_module, child_json);
            }
        }
    }
}

static void
node_add_children_with_metadata_recursive(struct lys_node *node, struct lys_module *module, json_object *parent)
{
    struct lys_module *cur_module;
    struct lys_node *child;
    json_object *node_json;
    char *json_name;

    /* add node metadata */
    if (node_add_metadata(node, module, parent)) {
        ERROR("Internal: metadata duplicate for \"%s\".", node->name);
        return;
    }

    /* get node module */
    cur_module = node->module;
    if (cur_module->type) {
        cur_module = ((struct lys_submodule *)cur_module)->belongsto;
    }

    /* create JSON object for child metadata */
    node_json = json_object_new_object();
    if (cur_module == module) {
        json_object_object_add(parent, node->name, node_json);
    } else {
        asprintf(&json_name, "%s:%s", cur_module->name, node->name);
        json_object_object_add(parent, json_name, node_json);
        free(json_name);
    }

    LY_TREE_FOR(node->child, child) {
        node_add_children_with_metadata_recursive(child, cur_module, node_json);
    }
}

static json_object *
libyang_query(unsigned int session_key, const char *filter, int load_children)
{
    struct lys_node *node;
    struct session_with_mutex *locked_session;
    json_object *ret = NULL, *data;

    locked_session = session_get_locked(session_key, &ret);
    if (!locked_session) {
        ERROR("Locking failed or session not found.");
        goto finish;
    }

    locked_session->last_activity = time(NULL);

    /* collect schema metadata and create reply */
    node = ly_ctx_get_node(locked_session->ctx, filter);

    if (node) {
        pthread_mutex_lock(&json_lock);
        data = json_object_new_object();

        if (load_children) {
            node_add_children_with_metadata_recursive(node, NULL, data);
        } else {
            node_add_metadata(node, NULL, data);
        }

        pthread_mutex_unlock(&json_lock);
        ret = create_data_reply(json_object_to_json_string(data));
        json_object_put(data);
    } else {
        ret = create_error_reply("Failed to resolve XPath filter node.");
    }

    session_unlock(locked_session);

finish:
    return ret;
}

static json_object *
libyang_merge(unsigned int session_key, const char *config)
{
    struct lyd_node *data_tree = NULL, *sibling;
    struct session_with_mutex *locked_session;
    json_object *ret = NULL, *data_json = NULL;
    enum json_tokener_error err = 0;

    locked_session = session_get_locked(session_key, &ret);
    if (!locked_session) {
        ERROR("Locking failed or session not found.");
        goto finish;
    }

    locked_session->last_activity = time(NULL);

    data_tree = lyd_parse(locked_session->ctx, config, LYD_JSON, LYD_OPT_STRICT);
    if (!data_tree) {
        ERROR("Creating data tree failed.");
        ret = create_error_reply("Failed to create data tree from JSON config.");
        session_unlock(locked_session);
        goto finish;
    }

    session_unlock(locked_session);

    pthread_mutex_lock(&json_lock);
    data_json = json_tokener_parse_verbose(config, &err);
    if (!data_json) {
        ERROR("Parsing JSON config failed (%s).", json_tokener_error_desc(err));
        pthread_mutex_unlock(&json_lock);
        ret = create_error_reply(json_tokener_error_desc(err));
        goto finish;
    }

    /* go simultaneously through both trees and add metadata */
    LY_TREE_FOR(data_tree, sibling) {
        node_add_metadata_recursive(sibling, NULL, data_json);
    }
    pthread_mutex_unlock(&json_lock);
    ret = create_data_reply(json_object_to_json_string(data_json));

finish:
    LY_TREE_FOR(data_tree, sibling) {
        lyd_free(sibling);
    }
    json_object_put(data_json);
    return ret;
}

/**
 * @}
 *//* netconf_operations */

void
clb_print(NC_VERB_LEVEL level, const char *msg)
{
#define FOREACH(I) \
        I(NC_VERB_ERROR) I(NC_VERB_WARNING)

#define CASE(VAL) case VAL: ERROR("%s: %s", #VAL, msg); \
    break;

    switch (level) {
    FOREACH(CASE);
    case NC_VERB_VERBOSE:
    case NC_VERB_DEBUG:
        DEBUG("DEBUG: %s", msg);
        break;
    }
    if (level == NC_VERB_ERROR) {
        /* return global error */
        netconf_callback_error_process(NULL /* tag */, NULL /* type */,
                NULL /* severity */, NULL /* apptag */,
                NULL /* path */, msg, NULL /* attribute */,
                NULL /* element */, NULL /* ns */, NULL /* sid */);
    }
}

/**
 * Receive message from client over UNIX socket and return pointer to it.
 * Caller should free message memory.
 * \param[in] client    socket descriptor of client
 * \return pointer to message
 */
char *
get_framed_message(int client)
{
    /* read json in chunked framing */
    unsigned int buffer_size = 0;
    ssize_t buffer_len = 0;
    char *buffer = NULL;
    char c;
    ssize_t ret;
    int i, chunk_len;
    char chunk_len_str[12];

    while (1) {
        /* read chunk length */
        if ((ret = recv (client, &c, 1, 0)) != 1 || c != '\n') {
            if (buffer != NULL) {
                free (buffer);
                buffer = NULL;
            }
            break;
        }
        if ((ret = recv (client, &c, 1, 0)) != 1 || c != '#') {
            if (buffer != NULL) {
                free (buffer);
                buffer = NULL;
            }
            break;
        }
        i=0;
        memset (chunk_len_str, 0, 12);
        while ((ret = recv (client, &c, 1, 0) == 1 && (isdigit(c) || c == '#'))) {
            if (i==0 && c == '#') {
                if (recv (client, &c, 1, 0) != 1 || c != '\n') {
                    /* end but invalid */
                    if (buffer != NULL) {
                        free (buffer);
                        buffer = NULL;
                    }
                }
                /* end of message, double-loop break */
                goto msg_complete;
            }
            chunk_len_str[i++] = c;
            if (i==11) {
                ERROR("Message is too long, buffer for length is not big enought!!!!");
                break;
            }
        }
        if (c != '\n') {
            if (buffer != NULL) {
                free (buffer);
                buffer = NULL;
            }
            break;
        }
        chunk_len_str[i] = 0;
        if ((chunk_len = atoi (chunk_len_str)) == 0) {
            if (buffer != NULL) {
                free (buffer);
                buffer = NULL;
            }
            break;
        }
        buffer_size += chunk_len+1;
        buffer = realloc (buffer, sizeof(char)*buffer_size);
        memset(buffer + (buffer_size-chunk_len-1), 0, chunk_len+1);
        if ((ret = recv (client, buffer+buffer_len, chunk_len, 0)) == -1 || ret != chunk_len) {
            if (buffer != NULL) {
                free (buffer);
                buffer = NULL;
            }
            break;
        }
        buffer_len += ret;
    }
msg_complete:
    return buffer;
}

NC_DATASTORE
parse_datastore(const char *ds)
{
    if (strcmp(ds, "running") == 0) {
        return NC_DATASTORE_RUNNING;
    } else if (strcmp(ds, "startup") == 0) {
        return NC_DATASTORE_STARTUP;
    } else if (strcmp(ds, "candidate") == 0) {
        return NC_DATASTORE_CANDIDATE;
    } else if (strcmp(ds, "url") == 0) {
        return NC_DATASTORE_URL;
    } else if (strcmp(ds, "config") == 0) {
        return NC_DATASTORE_CONFIG;
    }
    return -1;
}

NC_EDIT_TESTOPT_TYPE
parse_testopt(const char *t)
{
    if (strcmp(t, "notset") == 0) {
        return NC_EDIT_TESTOPT_NOTSET;
    } else if (strcmp(t, "testset") == 0) {
        return NC_EDIT_TESTOPT_TESTSET;
    } else if (strcmp(t, "set") == 0) {
        return NC_EDIT_TESTOPT_SET;
    } else if (strcmp(t, "test") == 0) {
        return NC_EDIT_TESTOPT_TEST;
    }
    return NC_EDIT_TESTOPT_ERROR;
}

json_object *
create_error_reply(const char *errmess)
{
    json_object *reply, *array;

    pthread_mutex_lock(&json_lock);
    reply = json_object_new_object();
    array = json_object_new_array();
    json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
    json_object_array_add(array, json_object_new_string(errmess));
    json_object_object_add(reply, "errors", array);
    pthread_mutex_unlock(&json_lock);

    return reply;
}

json_object *
create_data_reply(const char *data)
{
    pthread_mutex_lock(&json_lock);
    json_object *reply = json_object_new_object();
    json_object_object_add(reply, "type", json_object_new_int(REPLY_DATA));
    json_object_object_add(reply, "data", json_object_new_string(data));
    pthread_mutex_unlock(&json_lock);
    return reply;
}

json_object *
create_ok_reply(void)
{
    pthread_mutex_lock(&json_lock);
    json_object *reply = json_object_new_object();
    reply = json_object_new_object();
    json_object_object_add(reply, "type", json_object_new_int(REPLY_OK));
    pthread_mutex_unlock(&json_lock);
    return reply;
}

json_object *
create_replies(void)
{
    json_object *replies;

    pthread_mutex_lock(&json_lock);
    replies = json_object_new_object();
    pthread_mutex_unlock(&json_lock);

    return replies;
}

void
add_reply(json_object *replies, json_object *reply, unsigned int session_key)
{
    char *str;

    asprintf(&str, "%u", session_key);

    pthread_mutex_lock(&json_lock);
    json_object_object_add(replies, str, reply);
    pthread_mutex_unlock(&json_lock);

    free(str);
}

char *
get_param_string(json_object *data, const char *name)
{
    json_object *js_tmp = NULL;
    char *res = NULL;
    if (json_object_object_get_ex(data, name, &js_tmp) == TRUE) {
        res = strdup(json_object_get_string(js_tmp));
    }
    return res;
}

json_object *
handle_op_connect(json_object *request)
{
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *pass = NULL;
    json_object *reply = NULL;
    unsigned int session_key = 0;
    struct nc_cpblts* cpblts = NULL;

    DEBUG("Request: connect");
    pthread_mutex_lock(&json_lock);

    host = get_param_string(request, "host");
    port = get_param_string(request, "port");
    user = get_param_string(request, "user");
    pass = get_param_string(request, "pass");

    pthread_mutex_unlock(&json_lock);

    DEBUG("host: %s, port: %s, user: %s", host, port, user);
    if ((host == NULL) || (user == NULL)) {
        ERROR("Cannot connect - insufficient input.");
        session_key = 0;
    } else {
        session_key = netconf_connect(host, port, user, pass, cpblts);
        DEBUG("Session key: %u", session_key);
    }
    if (cpblts != NULL) {
        nc_cpblts_free(cpblts);
    }

    GETSPEC_ERR_REPLY

    pthread_mutex_lock(&json_lock);
    if (session_key == 0) {
        /* negative reply */
        if (err_reply == NULL) {
            reply = json_object_new_object();
            json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
            json_object_object_add(reply, "error-message", json_object_new_string("Connecting NETCONF server failed."));
            ERROR("Connection failed.");
        } else {
            /* use filled err_reply from libnetconf's callback */
            reply = err_reply;
            ERROR("Connect - error from libnetconf's callback.");
        }
    } else {
        /* positive reply */
        reply = json_object_new_object();
        json_object_object_add(reply, "type", json_object_new_int(REPLY_OK));
        json_object_object_add(reply, "session", json_object_new_int(session_key));
    }
    memset(pass, 0, strlen(pass));
    pthread_mutex_unlock(&json_lock);
    CHECK_AND_FREE(host);
    CHECK_AND_FREE(user);
    CHECK_AND_FREE(port);
    CHECK_AND_FREE(pass);
    return reply;
}

json_object *
handle_op_disconnect(json_object *UNUSED(request), unsigned int session_key)
{
    json_object *reply;

    DEBUG("Request: disconnect (session %u)", session_key);

    if (netconf_close(session_key, &reply) != EXIT_SUCCESS) {
        CHECK_ERR_SET_REPLY_ERR("Get configuration information from device failed.")
    } else {
        reply = create_ok_reply();
    }

    return reply;
}

json_object *
handle_op_get(json_object *request, unsigned int session_key)
{
    char *filter = NULL;
    char *data = NULL;
    json_object *reply = NULL, *obj;
    int strict;

    DEBUG("Request: get (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    filter = get_param_string(request, "filter");
    if (json_object_object_get_ex(request, "strict", &obj) == FALSE) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Missing strict parameter.");
        return reply;
    }
    strict = json_object_get_boolean(obj);
    pthread_mutex_unlock(&json_lock);

    if ((data = netconf_get(session_key, filter, strict, &reply)) == NULL) {
        CHECK_ERR_SET_REPLY_ERR("Get information failed.")
    } else {
        reply = create_data_reply(data);
        free(data);
    }

    return reply;
}

json_object *
handle_op_getconfig(json_object *request, unsigned int session_key)
{
    NC_DATASTORE ds_type_s = -1;
    char *filter = NULL;
    char *data = NULL;
    char *source = NULL;
    json_object *reply = NULL, *obj;
    int strict;

    DEBUG("Request: get-config (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    filter = get_param_string(request, "filter");
    source = get_param_string(request, "source");
    if (source != NULL) {
        ds_type_s = parse_datastore(source);
    }
    if (json_object_object_get_ex(request, "strict", &obj) == FALSE) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Missing strict parameter.");
        return reply;
    }
    strict = json_object_get_boolean(obj);
    pthread_mutex_unlock(&json_lock);

    if ((int)ds_type_s == -1) {
        reply = create_error_reply("Invalid source repository type requested.");
        goto finalize;
    }

    if ((data = netconf_getconfig(session_key, ds_type_s, filter, strict, &reply)) == NULL) {
        CHECK_ERR_SET_REPLY_ERR("Get configuration operation failed.")
    } else {
        reply = create_data_reply(data);
        free(data);
    }

finalize:
    CHECK_AND_FREE(filter);
    CHECK_AND_FREE(source);
    return reply;
}

json_object *
handle_op_editconfig(json_object *request, unsigned int session_key, int idx)
{
    NC_DATASTORE ds_type_s = -1;
    NC_DATASTORE ds_type_t = -1;
    NC_EDIT_DEFOP_TYPE defop_type = NC_EDIT_DEFOP_NOTSET;
    NC_EDIT_ERROPT_TYPE erropt_type = 0;
    NC_EDIT_TESTOPT_TYPE testopt_type = NC_EDIT_TESTOPT_TESTSET;
    char *defop = NULL;
    char *erropt = NULL;
    char *config = NULL;
    char *source = NULL;
    char *target = NULL;
    char *testopt = NULL;
    char *urisource = NULL;
    json_object *reply = NULL, *configs, *obj;

    DEBUG("Request: edit-config (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    /* get parameters */
    target = get_param_string(request, "target");
    if (json_object_object_get_ex(request, "configs", &configs) == FALSE) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Missing configs parameter.");
        goto finalize;
    }
    obj = json_object_array_get_idx(configs, idx);
    config = strdup(json_object_get_string(obj));

    source = get_param_string(request, "source");
    defop = get_param_string(request, "default-operation");
    erropt = get_param_string(request, "error-option");
    urisource = get_param_string(request, "uri-source");
    testopt = get_param_string(request, "test-option");
    pthread_mutex_unlock(&json_lock);

    if (target != NULL) {
        ds_type_t = parse_datastore(target);
    }
    if (source != NULL) {
        ds_type_s = parse_datastore(source);
    } else {
        /* source is optional, default value is config */
        ds_type_s = NC_DATASTORE_CONFIG;
    }

    if (defop != NULL) {
        if (strcmp(defop, "merge") == 0) {
            defop_type = NC_EDIT_DEFOP_MERGE;
        } else if (strcmp(defop, "replace") == 0) {
            defop_type = NC_EDIT_DEFOP_REPLACE;
        } else if (strcmp(defop, "none") == 0) {
            defop_type = NC_EDIT_DEFOP_NONE;
        } else {
            reply = create_error_reply("Invalid default-operation parameter.");
            goto finalize;
        }
    } else {
        defop_type = NC_EDIT_DEFOP_NOTSET;
    }

    if (erropt != NULL) {
        if (strcmp(erropt, "continue-on-error") == 0) {
            erropt_type = NC_EDIT_ERROPT_CONT;
        } else if (strcmp(erropt, "stop-on-error") == 0) {
            erropt_type = NC_EDIT_ERROPT_STOP;
        } else if (strcmp(erropt, "rollback-on-error") == 0) {
            erropt_type = NC_EDIT_ERROPT_ROLLBACK;
        } else {
            reply = create_error_reply("Invalid error-option parameter.");
            goto finalize;
        }
    } else {
        erropt_type = 0;
    }

    if ((int)ds_type_t == -1) {
        reply = create_error_reply("Invalid target repository type requested.");
        goto finalize;
    }
    if (ds_type_s == NC_DATASTORE_CONFIG) {
        if (config == NULL) {
            reply = create_error_reply("Invalid config data parameter.");
            goto finalize;
        }
    } else if (ds_type_s == NC_DATASTORE_URL){
        if (urisource == NULL) {
            reply = create_error_reply("Invalid uri-source parameter.");
            goto finalize;
        }
        config = urisource;
    }

    if (testopt != NULL) {
        testopt_type = parse_testopt(testopt);
    } else {
        testopt_type = NC_EDIT_TESTOPT_TESTSET;
    }

    reply = netconf_editconfig(session_key, ds_type_s, ds_type_t, defop_type, erropt_type, testopt_type, config);

    CHECK_ERR_SET_REPLY

finalize:
    CHECK_AND_FREE(defop);
    CHECK_AND_FREE(erropt);
    CHECK_AND_FREE(config);
    CHECK_AND_FREE(source);
    CHECK_AND_FREE(urisource);
    CHECK_AND_FREE(target);
    CHECK_AND_FREE(testopt);

    return reply;
}

json_object *
handle_op_copyconfig(json_object *request, unsigned int session_key, int idx)
{
    NC_DATASTORE ds_type_s = -1;
    NC_DATASTORE ds_type_t = -1;
    char *config = NULL;
    char *target = NULL;
    char *source = NULL;
    char *uri_src = NULL;
    char *uri_trg = NULL;
    json_object *reply = NULL, *configs, *obj;

    DEBUG("Request: copy-config (session %u)", session_key);

    /* get parameters */
    pthread_mutex_lock(&json_lock);
    target = get_param_string(request, "target");
    source = get_param_string(request, "source");
    uri_src = get_param_string(request, "uri-source");
    uri_trg = get_param_string(request, "uri-target");
    if (!strcmp(source, "config")) {
        if (json_object_object_get_ex(request, "configs", &configs) == FALSE) {
            pthread_mutex_unlock(&json_lock);
            reply = create_error_reply("Missing configs parameter.");
            goto finalize;
        }
        obj = json_object_array_get_idx(configs, idx);
        if (!obj) {
            pthread_mutex_unlock(&json_lock);
            reply = create_error_reply("Configs array parameter shorter than sessions.");
            goto finalize;
        }
        config = strdup(json_object_get_string(obj));
    }
    pthread_mutex_unlock(&json_lock);

    if (target != NULL) {
        ds_type_t = parse_datastore(target);
    }
    if (source != NULL) {
        ds_type_s = parse_datastore(source);
    }

    if ((int)ds_type_s == -1) {
        /* invalid source datastore specified */
        reply = create_error_reply("Invalid source repository type requested.");
        goto finalize;
    }

    if ((int)ds_type_t == -1) {
        /* invalid target datastore specified */
        reply = create_error_reply("Invalid target repository type requested.");
        goto finalize;
    }

    if (ds_type_s == NC_DATASTORE_URL) {
        if (uri_src == NULL) {
            uri_src = "";
        }
    }
    if (ds_type_t == NC_DATASTORE_URL) {
        if (uri_trg == NULL) {
            uri_trg = "";
        }
    }
    reply = netconf_copyconfig(session_key, ds_type_s, ds_type_t, config, uri_src, uri_trg);

    CHECK_ERR_SET_REPLY

finalize:
    CHECK_AND_FREE(config);
    CHECK_AND_FREE(target);
    CHECK_AND_FREE(source);
    CHECK_AND_FREE(uri_src);
    CHECK_AND_FREE(uri_trg);

    return reply;
}

json_object *
handle_op_deleteconfig(json_object *request, unsigned int session_key)
{
    json_object *reply;
    NC_DATASTORE ds_type = -1;
    char *target, *url;

    DEBUG("Request: delete-config (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    target = get_param_string(request, "target");
    url = get_param_string(request, "url");
    pthread_mutex_unlock(&json_lock);

    if (target != NULL) {
        ds_type = parse_datastore(target);
    }
    if ((int)ds_type == -1) {
        reply = create_error_reply("Invalid target repository type requested.");
        goto finalize;
    }
    if (ds_type == NC_DATASTORE_URL) {
        if (!url) {
            url = "";
        }
    }

    reply = netconf_deleteconfig(session_key, ds_type, url);

    CHECK_ERR_SET_REPLY
    if (reply == NULL) {
        reply = create_ok_reply();
    }

finalize:
    CHECK_AND_FREE(target);
    CHECK_AND_FREE(url);
    return reply;
}

json_object *
handle_op_lock(json_object *request, unsigned int session_key)
{
    json_object *reply;
    NC_DATASTORE ds_type = -1;
    char *target;

    DEBUG("Request: lock (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    target = get_param_string(request, "target");
    pthread_mutex_unlock(&json_lock);

    if (target != NULL) {
        ds_type = parse_datastore(target);
    }
    if ((int)ds_type == -1) {
        reply = create_error_reply("Invalid target repository type requested.");
        goto finalize;
    }

    reply = netconf_lock(session_key, ds_type);

    CHECK_ERR_SET_REPLY
    if (reply == NULL) {
        reply = create_ok_reply();
    }

finalize:
    CHECK_AND_FREE(target);
    return reply;
}

json_object *
handle_op_unlock(json_object *request, unsigned int session_key)
{
    json_object *reply;
    NC_DATASTORE ds_type = -1;
    char *target;

    DEBUG("Request: unlock (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    target = get_param_string(request, "target");
    pthread_mutex_unlock(&json_lock);

    if (target != NULL) {
        ds_type = parse_datastore(target);
    }
    if ((int)ds_type == -1) {
        reply = create_error_reply("Invalid target repository type requested.");
        goto finalize;
    }

    reply = netconf_unlock(session_key, ds_type);

    CHECK_ERR_SET_REPLY
    if (reply == NULL) {
        reply = create_ok_reply();
    }

finalize:
    CHECK_AND_FREE(target);
    return reply;
}

json_object *
handle_op_kill(json_object *request, unsigned int session_key)
{
    json_object *reply = NULL;
    char *sid = NULL;

    DEBUG("Request: kill-session (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    sid = get_param_string(request, "session-id");
    pthread_mutex_unlock(&json_lock);

    if (sid == NULL) {
        reply = create_error_reply("Missing session-id parameter.");
        goto finalize;
    }

    reply = netconf_killsession(session_key, sid);

    CHECK_ERR_SET_REPLY

finalize:
    CHECK_AND_FREE(sid);
    return reply;
}

json_object *
handle_op_info(json_object *UNUSED(request), unsigned int session_key)
{
    json_object *reply = NULL;
    struct session_with_mutex *locked_session = NULL;
    DEBUG("Request: get info about session %u", session_key);

    DEBUG("LOCK wrlock %s", __func__);
    if (pthread_rwlock_rdlock(&session_lock) != 0) {
        ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
    }

    for (locked_session = netconf_sessions_list;
         locked_session && (locked_session->session_key != session_key);
         locked_session = locked_session->next);
    if (locked_session != NULL) {
        DEBUG("LOCK mutex %s", __func__);
        pthread_mutex_lock(&locked_session->lock);
        DEBUG("UNLOCK wrlock %s", __func__);
        if (pthread_rwlock_unlock(&session_lock) != 0) {
            ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        }
        if (locked_session->hello_message != NULL) {
            reply = locked_session->hello_message;
        } else {
            reply = create_error_reply("Invalid session identifier.");
        }
        DEBUG("UNLOCK mutex %s", __func__);
        pthread_mutex_unlock(&locked_session->lock);
    } else {
        DEBUG("UNLOCK wrlock %s", __func__);
        if (pthread_rwlock_unlock(&session_lock) != 0) {
            ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        }
        reply = create_error_reply("Invalid session identifier.");
    }

    return reply;
}

json_object *
handle_op_generic(json_object *request, unsigned int session_key, int idx)
{
    json_object *reply = NULL, *contents, *obj;
    char *config = NULL;
    char *data = NULL;

    DEBUG("Request: generic request (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    if (json_object_object_get_ex(request, "contents", &contents) == FALSE) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Missing contents parameter.");
        goto finalize;
    }
    obj = json_object_array_get_idx(contents, idx);
    if (!obj) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Contents array parameter shorter than sessions.");
        goto finalize;
    }
    config = strdup(json_object_get_string(obj));
    pthread_mutex_unlock(&json_lock);

    reply = netconf_generic(session_key, config, &data);
    if (reply == NULL) {
        GETSPEC_ERR_REPLY
        if (err_reply != NULL) {
            /* use filled err_reply from libnetconf's callback */
            reply = err_reply;
        }
    } else {
        if (data == NULL) {
            pthread_mutex_lock(&json_lock);
            reply = json_object_new_object();
            json_object_object_add(reply, "type", json_object_new_int(REPLY_OK));
            pthread_mutex_unlock(&json_lock);
        } else {
            reply = create_data_reply(data);
            free(data);
        }
    }

finalize:
    CHECK_AND_FREE(config);
    return reply;
}

json_object *
handle_op_getschema(json_object *request, unsigned int session_key)
{
    char *data = NULL;
    char *identifier = NULL;
    char *version = NULL;
    char *format = NULL;
    json_object *reply = NULL;

    DEBUG("Request: get-schema (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    identifier = get_param_string(request, "identifier");
    version = get_param_string(request, "version");
    format = get_param_string(request, "format");
    pthread_mutex_unlock(&json_lock);

    if (identifier == NULL) {
        reply = create_error_reply("No identifier for get-schema supplied.");
        goto finalize;
    }

    DEBUG("get-schema(version: %s, format: %s)", version, format);
    if ((data = netconf_getschema(session_key, identifier, version, format, &reply)) == NULL) {
        CHECK_ERR_SET_REPLY_ERR("Get models operation failed.")
    } else {
        reply = create_data_reply(data);
        free(data);
    }

finalize:
    CHECK_AND_FREE(identifier);
    CHECK_AND_FREE(version);
    CHECK_AND_FREE(format);
    return reply;
}

json_object *
handle_op_reloadhello(json_object *UNUSED(request), unsigned int session_key)
{
    struct nc_session *temp_session = NULL;
    struct session_with_mutex * locked_session = NULL;
    json_object *reply = NULL;

    DEBUG("Request: reload hello (session %u)", session_key);

    DEBUG("LOCK wrlock %s", __func__);
    if (pthread_rwlock_wrlock(&session_lock) != 0) {
        ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        return NULL;
    }

    for (locked_session = netconf_sessions_list;
         locked_session && (locked_session->session_key != session_key);
         locked_session = locked_session->next);
    if ((locked_session != NULL) && (locked_session->hello_message != NULL)) {
        DEBUG("LOCK mutex %s", __func__);
        pthread_mutex_lock(&locked_session->lock);
        DEBUG("creating temporary NC session.");
        temp_session = nc_session_connect_channel(locked_session->session, NULL);
        if (temp_session != NULL) {
            prepare_status_message(locked_session, temp_session);
            DEBUG("closing temporal NC session.");
            nc_session_free(temp_session);
            temp_session = NULL;
        } else {
            DEBUG("Reload hello failed due to channel establishment");
            reply = create_error_reply("Reload was unsuccessful, connection failed.");
        }
        DEBUG("UNLOCK mutex %s", __func__);
        pthread_mutex_unlock(&locked_session->lock);
        DEBUG("UNLOCK wrlock %s", __func__);
        if (pthread_rwlock_unlock(&session_lock) != 0) {
            ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        }
    } else {
        DEBUG("UNLOCK wrlock %s", __func__);
        if (pthread_rwlock_unlock(&session_lock) != 0) {
            ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        }
        reply = create_error_reply("Invalid session identifier.");
    }

    if ((reply == NULL) && (locked_session->hello_message != NULL)) {
        reply = locked_session->hello_message;
    }

    return reply;
}

void
notification_history(time_t eventtime, const char *content)
{
    json_object *notif_history_array = (json_object *)pthread_getspecific(notif_history_key);
    if (notif_history_array == NULL) {
        ERROR("No list of notification history found.");
        return;
    }
    DEBUG("Got notification from history %lu.", (long unsigned)eventtime);
    pthread_mutex_lock(&json_lock);
    json_object *notif = json_object_new_object();
    if (notif == NULL) {
        ERROR("Could not allocate memory for notification (json).");
        goto failed;
    }
    json_object_object_add(notif, "eventtime", json_object_new_int64(eventtime));
    json_object_object_add(notif, "content", json_object_new_string(content));
    json_object_array_add(notif_history_array, notif);
failed:
    pthread_mutex_unlock(&json_lock);
}

json_object *
handle_op_ntfgethistory(json_object *request, unsigned int session_key)
{
    json_object *reply = NULL;
    json_object *js_tmp = NULL;
    struct session_with_mutex *locked_session = NULL;
    struct nc_session *temp_session = NULL;
    nc_rpc *rpc = NULL;
    time_t start = 0;
    time_t stop = 0;
    int64_t from = 0, to = 0;

    DEBUG("Request: get notification history (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    if (json_object_object_get_ex(request, "from", &js_tmp) == TRUE) {
        from = json_object_get_int64(js_tmp);
    }
    if (json_object_object_get_ex(request, "to", &js_tmp) == TRUE) {
        to = json_object_get_int64(js_tmp);
    }
    pthread_mutex_unlock(&json_lock);

    start = time(NULL) + from;
    stop = time(NULL) + to;

    DEBUG("notification history interval %li %li", (long int)from, (long int)to);

    DEBUG("LOCK wrlock %s", __func__);
    if (pthread_rwlock_rdlock(&session_lock) != 0) {
        ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        reply = create_error_reply("Internal lock failed.");
        goto finalize;
    }

    for (locked_session = netconf_sessions_list;
         locked_session && (locked_session->session_key != session_key);
         locked_session = locked_session->next);
    if (locked_session != NULL) {
        DEBUG("LOCK mutex %s", __func__);
        pthread_mutex_lock(&locked_session->lock);
        DEBUG("UNLOCK wrlock %s", __func__);
        if (pthread_rwlock_unlock(&session_lock) != 0) {
            ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        }
        DEBUG("creating temporal NC session.");
        temp_session = nc_session_connect_channel(locked_session->session, NULL);
        if (temp_session != NULL) {
            rpc = nc_rpc_subscribe(NULL /* stream */, NULL /* filter */, &start, &stop);
            if (rpc == NULL) {
                DEBUG("UNLOCK mutex %s", __func__);
                pthread_mutex_unlock(&locked_session->lock);
                DEBUG("notifications: creating an rpc request failed.");
                reply = create_error_reply("notifications: creating an rpc request failed.");
                goto finalize;
            }

            DEBUG("Send NC subscribe.");
            /** \todo replace with sth like netconf_op(http_server, session_hash, rpc) */
            json_object *res = netconf_unlocked_op(temp_session, rpc);
            if (res != NULL) {
                DEBUG("UNLOCK mutex %s", __func__);
                pthread_mutex_unlock(&locked_session->lock);
                DEBUG("Subscription RPC failed.");
                reply = res;
                goto finalize;
            }
            rpc = NULL; /* just note that rpc is already freed by send_recv_process() */

            DEBUG("UNLOCK mutex %s", __func__);
            pthread_mutex_unlock(&locked_session->lock);
            DEBUG("LOCK mutex %s", __func__);
            pthread_mutex_lock(&ntf_history_lock);
            pthread_mutex_lock(&json_lock);
            json_object *notif_history_array = json_object_new_array();
            pthread_mutex_unlock(&json_lock);
            if (pthread_setspecific(notif_history_key, notif_history_array) != 0) {
                ERROR("notif_history: cannot set thread-specific hash value.");
            }

            ncntf_dispatch_receive(temp_session, notification_history);

            pthread_mutex_lock(&json_lock);
            reply = json_object_new_object();
            json_object_object_add(reply, "notifications", notif_history_array);
            //json_object_put(notif_history_array);
            pthread_mutex_unlock(&json_lock);

            DEBUG("UNLOCK mutex %s", __func__);
            pthread_mutex_unlock(&ntf_history_lock);
            DEBUG("closing temporal NC session.");
            nc_session_free(temp_session);
            temp_session = NULL;
        } else {
            DEBUG("UNLOCK mutex %s", __func__);
            pthread_mutex_unlock(&locked_session->lock);
            DEBUG("Get history of notification failed due to channel establishment");
            reply = create_error_reply("Get history of notification was unsuccessful, connection failed.");
        }
    } else {
        DEBUG("UNLOCK wrlock %s", __func__);
        if (pthread_rwlock_unlock(&session_lock) != 0) {
            ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
        }
        reply = create_error_reply("Invalid session identifier.");
    }

finalize:
    return reply;
}

json_object *
handle_op_validate(json_object *request, unsigned int session_key)
{
    json_object *reply = NULL;
    char *target = NULL;
    char *url = NULL;
    nc_rpc *rpc = NULL;
    NC_DATASTORE target_ds;

    DEBUG("Request: validate datastore (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    target = get_param_string(request, "target");
    url = get_param_string(request, "url");
    pthread_mutex_unlock(&json_lock);


    if (target == NULL) {
        reply = create_error_reply("Missing target parameter.");
        goto finalize;
    }

    /* validation */
    target_ds = parse_datastore(target);
    if (target_ds == NC_DATASTORE_URL) {
        if (url != NULL) {
            rpc = nc_rpc_validate(target_ds, url);
        }
    } else if ((target_ds == NC_DATASTORE_RUNNING) || (target_ds == NC_DATASTORE_STARTUP)
            || (target_ds == NC_DATASTORE_CANDIDATE)) {
        rpc = nc_rpc_validate(target_ds);
    }
    if (rpc == NULL) {
        DEBUG("mod_netconf: creating rpc request failed");
        reply = create_error_reply("Creation of RPC request failed.");
        goto finalize;
    }

    if ((reply = netconf_op(session_key, rpc, NULL)) == NULL) {
        CHECK_ERR_SET_REPLY

        if (reply == NULL) {
            DEBUG("Request: validation ok.");
            reply = create_ok_reply();
        }
    }
    nc_rpc_free (rpc);

finalize:
    CHECK_AND_FREE(target);
    CHECK_AND_FREE(url);
    return reply;
}

json_object *
handle_op_query(json_object *request, unsigned int session_key, int idx)
{
    json_object *reply = NULL, *filters, *obj;
    char *filter = NULL;
    int load_children = 0;

    DEBUG("Request: query (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    if (json_object_object_get_ex(request, "filters", &filters) == FALSE) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Missing filters parameter.");
        goto finalize;
    }
    obj = json_object_array_get_idx(filters, idx);
    if (!obj) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Filters array parameter shorter than sessions.");
        goto finalize;
    }
    filter = strdup(json_object_get_string(obj));
    if (json_object_object_get_ex(request, "load_children", &obj) == TRUE) {
        load_children = json_object_get_boolean(obj);
    }
    pthread_mutex_unlock(&json_lock);

    reply = libyang_query(session_key, filter, load_children);

    CHECK_ERR_SET_REPLY
    if (!reply) {
        reply = create_error_reply("Query failed.");
    }

finalize:
    CHECK_AND_FREE(filter);
    return reply;
}

json_object *
handle_op_merge(json_object *request, unsigned int session_key, int idx)
{
    json_object *reply = NULL, *configs, *obj;
    char *config = NULL;

    DEBUG("Request: merge (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    if (json_object_object_get_ex(request, "configurations", &configs) == FALSE) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Missing configurations parameter.");
        goto finalize;
    }
    obj = json_object_array_get_idx(configs, idx);
    if (!obj) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Filters array parameter shorter than sessions.");
        goto finalize;
    }
    config = strdup(json_object_get_string(obj));
    pthread_mutex_unlock(&json_lock);

    reply = libyang_merge(session_key, config);

    CHECK_ERR_SET_REPLY
    if (!reply) {
        reply = create_error_reply("Merge failed.");
    }

finalize:
    CHECK_AND_FREE(config);
    return reply;
}

void *
thread_routine(void *arg)
{
    void *retval = NULL;
    struct pollfd fds;
    json_object *request = NULL, *replies = NULL, *reply, *sessions = NULL;
    json_object *js_tmp = NULL;
    int operation = (-1), count, i;
    int status = 0;
    const char *msgtext;
    unsigned int session_key = 0;
    char *chunked_out_msg = NULL;
    int client = ((struct pass_to_thread *)arg)->client;

    char *buffer = NULL;

    /* init thread specific err_reply memory */
    create_err_reply_p();

    while (!isterminated) {
        fds.fd = client;
        fds.events = POLLIN;
        fds.revents = 0;

        status = poll(&fds, 1, 1000);

        if (status == 0 || (status == -1 && (errno == EAGAIN || (errno == EINTR && isterminated == 0)))) {
            /* poll was interrupted - check if the isterminated is set and if not, try poll again */
            continue;
        } else if (status < 0) {
            /* 0:  poll time outed
             *     close socket and ignore this request from the client, it can try it again
             * -1: poll failed
             *     something wrong happend, close this socket and wait for another request
             */
            close(client);
            break;
        }
        /* status > 0 */

        /* check the status of the socket */

        /* if nothing to read and POLLHUP (EOF) or POLLERR set */
        if ((fds.revents & POLLHUP) || (fds.revents & POLLERR)) {
            /* close client's socket (it's probably already closed by client */
            close(client);
            break;
        }

        DEBUG("Get framed message...");
        buffer = get_framed_message(client);

        DEBUG("Check read buffer.");
        if (buffer != NULL) {
            enum json_tokener_error jerr;
            pthread_mutex_lock(&json_lock);
            request = json_tokener_parse_verbose(buffer, &jerr);
            if (jerr != json_tokener_success) {
                ERROR("JSON parsing error");
                pthread_mutex_unlock(&json_lock);
                continue;
            }

            if (json_object_object_get_ex(request, "type", &js_tmp) == TRUE) {
                operation = json_object_get_int(js_tmp);
            }
            pthread_mutex_unlock(&json_lock);
            if (operation == -1) {
                replies = create_replies();
                add_reply(replies, create_error_reply("Missing operation type from frontend."), 0);
                goto send_reply;
            }

            if ((operation < 4) || ((operation > 19) && (operation < 100)) || (operation > 101)) {
                DEBUG("Unknown mod_netconf operation requested (%d)", operation);
                replies = create_replies();
                add_reply(replies, create_error_reply("Operation not supported."), 0);
                goto send_reply;
            }

            DEBUG("operation %d", operation);

            /* null global JSON error-reply */
            clean_err_reply();

            /* clean replies envelope */
            if (replies != NULL) {
                pthread_mutex_lock(&json_lock);
                json_object_put(replies);
                pthread_mutex_unlock(&json_lock);
            }
            replies = create_replies();

            if (operation == MSG_CONNECT) {
                count = 1;
            } else {
                pthread_mutex_lock(&json_lock);
                if (json_object_object_get_ex(request, "sessions", &sessions) == FALSE) {
                    add_reply(replies, create_error_reply("Operation missing \"sessions\" arg"), 0);
                    goto send_reply;
                }
                count = json_object_array_length(sessions);
                pthread_mutex_unlock(&json_lock);
            }

            for (i = 0; i < count; ++i) {
                if (operation != MSG_CONNECT) {
                    js_tmp = json_object_array_get_idx(sessions, i);
                    session_key = json_object_get_int(js_tmp);
                }

                /* process required operation */
                switch (operation) {
                case MSG_CONNECT:
                    reply = handle_op_connect(request);
                    break;
                case MSG_DISCONNECT:
                    reply = handle_op_disconnect(request, session_key);
                    break;
                case MSG_GET:
                    reply = handle_op_get(request, session_key);
                    break;
                case MSG_GETCONFIG:
                    reply = handle_op_getconfig(request, session_key);
                    break;
                case MSG_EDITCONFIG:
                    reply = handle_op_editconfig(request, session_key, i);
                    break;
                case MSG_COPYCONFIG:
                    reply = handle_op_copyconfig(request, session_key, i);
                    break;
                case MSG_DELETECONFIG:
                    reply = handle_op_deleteconfig(request, session_key);
                    break;
                case MSG_LOCK:
                    reply = handle_op_lock(request, session_key);
                    break;
                case MSG_UNLOCK:
                    reply = handle_op_unlock(request, session_key);
                    break;
                case MSG_KILL:
                    reply = handle_op_kill(request, session_key);
                    break;
                case MSG_INFO:
                    reply = handle_op_info(request, session_key);
                    break;
                case MSG_GENERIC:
                    reply = handle_op_generic(request, session_key, i);
                    break;
                case MSG_GETSCHEMA:
                    reply = handle_op_getschema(request, session_key);
                    break;
                case MSG_RELOADHELLO:
                    reply = handle_op_reloadhello(request, session_key);
                    break;
                case MSG_NTF_GETHISTORY:
                    reply = handle_op_ntfgethistory(request, session_key);
                    break;
                case MSG_VALIDATE:
                    reply = handle_op_validate(request, session_key);
                    break;
                case SCH_QUERY:
                    reply = handle_op_query(request, session_key, i);
                    break;
                case SCH_MERGE:
                    reply = handle_op_merge(request, session_key, i);
                    break;
                }

                add_reply(replies, reply, session_key);
            }

            /* free parameters */
            operation = (-1);

            DEBUG("Clean request json object.");
            if (request != NULL) {
                pthread_mutex_lock(&json_lock);
                json_object_put(request);
                pthread_mutex_unlock(&json_lock);
            }
            DEBUG("Send reply json object.");

send_reply:
            /* send reply to caller */
            if (replies) {
                pthread_mutex_lock(&json_lock);
                msgtext = json_object_to_json_string(replies);
                if (asprintf(&chunked_out_msg, "\n#%d\n%s\n##\n", (int)strlen(msgtext), msgtext) == -1) {
                    if (buffer != NULL) {
                        free(buffer);
                        buffer = NULL;
                    }
                    pthread_mutex_unlock(&json_lock);
                    break;
                }
                pthread_mutex_unlock(&json_lock);

                DEBUG("Send framed reply json object.");
                send(client, chunked_out_msg, strlen(chunked_out_msg) + 1, 0);
                DEBUG("Clean reply json object.");
                pthread_mutex_lock(&json_lock);
                json_object_put(replies);
                replies = NULL;
                DEBUG("Clean message buffer.");
                CHECK_AND_FREE(chunked_out_msg);
                chunked_out_msg = NULL;
                if (buffer) {
                    free(buffer);
                    buffer = NULL;
                }
                pthread_mutex_unlock(&json_lock);
                clean_err_reply();
            } else {
                ERROR("Reply is NULL, shouldn't be...");
                continue;
            }
        }
    }
    free(arg);
    free_err_reply();

    return retval;
}

/**
 * \brief Close all open NETCONF sessions.
 *
 * During termination of mod_netconf, it is useful to close all remaining
 * sessions. This function iterates over the list of sessions and close them
 * all.
 */
static void
close_all_nc_sessions(void)
{
    struct session_with_mutex *locked_session, *next_session;
    int ret;

    /* get exclusive access to sessions_list (conns) */
    DEBUG("LOCK wrlock %s", __func__);
    if ((ret = pthread_rwlock_wrlock (&session_lock)) != 0) {
        ERROR("Error while locking rwlock: %d (%s)", ret, strerror(ret));
        return;
    }
    for (next_session = netconf_sessions_list; next_session;) {
        locked_session = next_session;
        next_session = locked_session->next;

        /* close_and_free_session handles locking on its own */
        DEBUG("Closing NETCONF session %u (SID %s).", locked_session->session_key, nc_session_get_id(locked_session->session));
        close_and_free_session(locked_session);
    }
    netconf_sessions_list = NULL;

    /* get exclusive access to sessions_list (conns) */
    DEBUG("UNLOCK wrlock %s", __func__);
    if (pthread_rwlock_unlock (&session_lock) != 0) {
        ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
    }
}

static void
check_timeout_and_close(void)
{
    struct nc_session *ns = NULL;
    struct session_with_mutex *locked_session = NULL;
    time_t current_time = time(NULL);
    int ret;

    /* get exclusive access to sessions_list (conns) */
    if ((ret = pthread_rwlock_wrlock(&session_lock)) != 0) {
        DEBUG("Error while locking rwlock: %d (%s)", ret, strerror(ret));
        return;
    }
    for (locked_session = netconf_sessions_list; locked_session; locked_session = locked_session->next) {
        ns = locked_session->session;
        if (ns == NULL) {
            continue;
        }
        pthread_mutex_lock(&locked_session->lock);
        if ((current_time - locked_session->last_activity) > ACTIVITY_TIMEOUT) {
            DEBUG("Closing NETCONF session %u (SID %s).", locked_session->session_key, nc_session_get_id(locked_session->session));

            /* close_and_free_session handles locking on its own */
            close_and_free_session(locked_session);
        } else {
            pthread_mutex_unlock(&locked_session->lock);
        }
    }
    /* get exclusive access to sessions_list (conns) */
    if (pthread_rwlock_unlock(&session_lock) != 0) {
        ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
    }
}


/**
 * This is actually implementation of NETCONF client
 * - requests are received from UNIX socket in the predefined format
 * - results are replied through the same way
 * - the daemon run as a separate process
 *
 */
static void
forked_proc(void)
{
    struct timeval tv;
    struct sockaddr_un local, remote;
    int lsock, client, ret, i, pthread_count = 0;
    unsigned int olds = 0, timediff = 0;
    socklen_t len;
    struct pass_to_thread *arg;
    pthread_t *ptids = calloc(1, sizeof(pthread_t));
    struct timespec maxtime;
    pthread_rwlockattr_t lock_attrs;
    #ifdef WITH_NOTIFICATIONS
    char use_notifications = 0;
    #endif

    /* wait at most 5 seconds for every thread to terminate */
    maxtime.tv_sec = 5;
    maxtime.tv_nsec = 0;

#ifdef HAVE_UNIXD_SETUP_CHILD
    /* change uid and gid of process for security reasons */
    unixd_setup_child();
#else
# ifdef SU_GROUP
    if (strlen(SU_GROUP) > 0) {
        struct group *g = getgrnam(SU_GROUP);
        if (g == NULL) {
            ERROR("GID (%s) was not found.", SU_GROUP);
            return;
        }
        if (setgid(g->gr_gid) != 0) {
            ERROR("Switching to %s GID failed. (%s)", SU_GROUP, strerror(errno));
            return;
        }
    }
# else
    DEBUG("no SU_GROUP");
# endif
# ifdef SU_USER
    if (strlen(SU_USER) > 0) {
        struct passwd *p = getpwnam(SU_USER);
        if (p == NULL) {
            ERROR("UID (%s) was not found.", SU_USER);
            return;
        }
        if (setuid(p->pw_uid) != 0) {
            ERROR("Switching to UID %s failed. (%s)", SU_USER, strerror(errno));
            return;
        }
    }
# else
    DEBUG("no SU_USER");
# endif
#endif

    /* try to remove if exists */
    unlink(sockname);

    /* create listening UNIX socket to accept incoming connections */
    if ((lsock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
        ERROR("Creating socket failed (%s)", strerror(errno));
        goto error_exit;
    }

    local.sun_family = AF_UNIX;
    strncpy(local.sun_path, sockname, sizeof(local.sun_path));
    len = offsetof(struct sockaddr_un, sun_path) + strlen(local.sun_path);

    if (bind(lsock, (struct sockaddr *)&local, len) == -1) {
        if (errno == EADDRINUSE) {
            ERROR("mod_netconf socket address already in use");
            goto error_exit;
        }
        ERROR("Binding socket failed (%s)", strerror(errno));
        goto error_exit;
    }

    if (listen(lsock, MAX_SOCKET_CL) == -1) {
        ERROR("Setting up listen socket failed (%s)", strerror(errno));
        goto error_exit;
    }
    chmod(sockname, S_IWUSR | S_IWGRP | S_IWOTH | S_IRUSR | S_IRGRP | S_IROTH);

    uid_t user = -1;
    if (strlen(CHOWN_USER) > 0) {
        struct passwd *p = getpwnam(CHOWN_USER);
        if (p != NULL) {
            user = p->pw_uid;
        }
    }
    gid_t group = -1;
    if (strlen(CHOWN_GROUP) > 0) {
        struct group *g = getgrnam(CHOWN_GROUP);
        if (g != NULL) {
            group = g->gr_gid;
        }
    }
    if (chown(sockname, user, group) == -1) {
        ERROR("Chown on socket file failed (%s).", strerror(errno));
    }

    /* prepare internal lists */

    #ifdef WITH_NOTIFICATIONS
    if (notification_init() == -1) {
        ERROR("libwebsockets initialization failed");
        use_notifications = 0;
    } else {
        use_notifications = 1;
    }
    #endif

    /* setup libnetconf's callbacks */
    nc_verbosity(NC_VERB_DEBUG);
    nc_callback_print(clb_print);
    nc_callback_ssh_host_authenticity_check(netconf_callback_ssh_hostkey_check);
    nc_callback_sshauth_interactive(netconf_callback_sshauth_interactive);
    nc_callback_sshauth_password(netconf_callback_sshauth_password);
    nc_callback_sshauth_passphrase(netconf_callback_sshauth_passphrase);
    nc_callback_error_reply(netconf_callback_error_process);

    /* disable publickey authentication */
    nc_ssh_pref(NC_SSH_AUTH_PUBLIC_KEYS, -1);

    /* create mutex protecting session list */
    pthread_rwlockattr_init(&lock_attrs);
    /* rwlock is shared only with threads in this process */
    pthread_rwlockattr_setpshared(&lock_attrs, PTHREAD_PROCESS_PRIVATE);
    /* create rw lock */
    if (pthread_rwlock_init(&session_lock, &lock_attrs) != 0) {
        ERROR("Initialization of mutex failed: %d (%s)", errno, strerror(errno));
        goto error_exit;
    }
    pthread_mutex_init(&ntf_history_lock, NULL);
    pthread_mutex_init(&json_lock, NULL);
    DEBUG("Initialization of notification history.");
    if (pthread_key_create(&notif_history_key, NULL) != 0) {
        ERROR("Initialization of notification history failed.");
    }
    if (pthread_key_create(&err_reply_key, NULL) != 0) {
        ERROR("Initialization of reply key failed.");
    }

    fcntl(lsock, F_SETFL, fcntl(lsock, F_GETFL, 0) | O_NONBLOCK);
    while (isterminated == 0) {
        gettimeofday(&tv, NULL);
        timediff = (unsigned int)tv.tv_sec - olds;
        #ifdef WITH_NOTIFICATIONS
        if (use_notifications == 1) {
            notification_handle();
        }
        #endif
        if (timediff > ACTIVITY_CHECK_INTERVAL) {
            check_timeout_and_close();
        }

        /* open incoming connection if any */
        len = sizeof(remote);
        client = accept(lsock, (struct sockaddr *) &remote, &len);
        if (client == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(SLEEP_TIME * 1000);
            continue;
        } else if (client == -1 && (errno == EINTR)) {
            continue;
        } else if (client == -1) {
            ERROR("Accepting mod_netconf client connection failed (%s)", strerror(errno));
            continue;
        }

        /* set client's socket as non-blocking */
        //fcntl(client, F_SETFL, fcntl(client, F_GETFL, 0) | O_NONBLOCK);

        arg = malloc(sizeof(struct pass_to_thread));
        arg->client = client;
        arg->netconf_sessions_list = netconf_sessions_list;

        /* start new thread. It will serve this particular request and then terminate */
        if ((ret = pthread_create (&ptids[pthread_count], NULL, thread_routine, (void *)arg)) != 0) {
            ERROR("Creating POSIX thread failed: %d\n", ret);
        } else {
            DEBUG("Thread %lu created", ptids[pthread_count]);
            pthread_count++;
            ptids = realloc (ptids, sizeof(pthread_t) * (pthread_count+1));
            ptids[pthread_count] = 0;
        }

        /* check if some thread already terminated, free some resources by joining it */
        for (i = 0; i < pthread_count; i++) {
            if (pthread_tryjoin_np(ptids[i], (void **)&arg) == 0) {
                DEBUG("Thread %lu joined with retval %p", ptids[i], arg);
                pthread_count--;
                if (pthread_count > 0) {
                    /* place last Thread ID on the place of joined one */
                    ptids[i] = ptids[pthread_count];
                }
            }
        }
        DEBUG("Running %d threads", pthread_count);
    }

    DEBUG("mod_netconf terminating...");
    /* join all threads */
    for (i = 0; i < pthread_count; i++) {
        pthread_timedjoin_np(ptids[i], (void **)&arg, &maxtime);
    }

    #ifdef WITH_NOTIFICATIONS
    notification_close();
    #endif

    /* close all NETCONF sessions */
    close_all_nc_sessions();

    /* destroy rwlock */
    pthread_rwlock_destroy(&session_lock);
    pthread_rwlockattr_destroy(&lock_attrs);

    DEBUG("Exiting from the mod_netconf daemon");

    free(ptids);
    close(lsock);
    exit(0);
    return;

error_exit:
    close(lsock);
    free(ptids);
    return;
}

int
main(int argc, char **argv)
{
    struct sigaction action;
    sigset_t block_mask;

    if (argc > 1) {
        sockname = argv[1];
    } else {
        sockname = SOCKET_FILENAME;
    }

    sigfillset(&block_mask);
    action.sa_handler = signal_handler;
    action.sa_mask = block_mask;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    forked_proc();
    DEBUG("Terminated");
    return 0;
}
