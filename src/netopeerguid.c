/*!
 * \file netopeerguid.c
 * \brief NetopeerGUI daemon
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \date 2011
 * \date 2012
 * \date 2013
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
#define _GNU_SOURCE

#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pwd.h>
#include <syslog.h>
#include <errno.h>
#include <limits.h>
#include <grp.h>
#include <signal.h>
#include <pthread.h>
#include <ctype.h>

#include <nc_client.h>

#include "../config.h"

#ifdef WITH_NOTIFICATIONS
#include "notification_server.h"
#endif

#include "message_type.h"
#include "netopeerguid.h"

#define SCHEMA_DIR "/tmp/yang_models"
#define MAX_PROCS 5
#define SOCKET_FILENAME "/var/run/netopeerguid.sock"
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
int daemonize;

json_object *create_ok_reply(void);
json_object *create_data_reply(const char *data);
static char *netconf_getschema(unsigned int session_key, const char *identifier, const char *version,
                               const char *format, json_object **err);
static void node_add_metadata_recursive(struct lyd_node *data_tree, const struct lys_module *module,
                                        json_object *data_json_parent);
static void node_metadata_typedef(struct lys_tpdf *tpdf, json_object *parent);

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
netconf_callback_sshauth_passphrase(const char *UNUSED(priv_key_file))
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
netconf_callback_error_process(const char *message)
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
    int i;
    json_object *json_obj = NULL;
    json_object *js_tmp = NULL;
    char *old_sid = NULL;
    const char *j_old_sid = NULL;
    char str_port[6];
    const char **cpblts;
    struct lyd_node *yanglib, *module, *node;

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
        if (!old_sid) {
            /* we don't have old sid */
            asprintf(&old_sid, "%u", nc_session_get_id(session));
        }
        json_object_object_add(s->hello_message, "sid", json_object_new_string(old_sid));
        free(old_sid);
        old_sid = NULL;

        json_object_object_add(s->hello_message, "version", json_object_new_string((nc_session_get_version(session) ? "1.1":"1.0")));
        json_object_object_add(s->hello_message, "host", json_object_new_string(nc_session_get_host(session)));
        sprintf(str_port, "%u", nc_session_get_port(session));
        json_object_object_add(s->hello_message, "port", json_object_new_string(str_port));
        json_object_object_add(s->hello_message, "user", json_object_new_string(nc_session_get_username(session)));
        cpblts = nc_session_get_cpblts(session);
        if (cpblts) {
            json_obj = json_object_new_array();
            for (i = 0; cpblts[i]; ++i) {
                json_object_array_add(json_obj, json_object_new_string(cpblts[i]));
            }
            json_object_object_add(s->hello_message, "capabilities", json_obj);
        }

        yanglib = ly_ctx_info(nc_session_get_ctx(session));
        if (yanglib) {
            json_obj = json_object_new_array();
            LY_TREE_FOR(yanglib->child, module) {
                if (!strcmp(module->schema->name, "module")) {
                    LY_TREE_FOR(module->child, node) {
                        if (!strcmp(node->schema->name, "name")) {
                            json_object_array_add(json_obj, json_object_new_string(((struct lyd_node_leaf_list *)node)->value_str));
                            break;
                        }
                    }
                }
            }
            json_object_object_add(s->hello_message, "models", json_obj);

            lyd_free(yanglib);
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
session_user_activity(const char *username)
{
    struct session_with_mutex *sess;

    for (sess = netconf_sessions_list; sess; sess = sess->next) {
        if (!strcmp(nc_session_get_username(sess->session), username)) {
            sess->last_activity = time(NULL);
        }
    }
}

static void
session_unlock(struct session_with_mutex *locked_session)
{
    DEBUG("UNLOCK mutex %s", __func__);
    pthread_mutex_unlock(&locked_session->lock);
    DEBUG("UNLOCK wrlock %s", __func__);
    pthread_rwlock_unlock(&session_lock);
}

static void
node_metadata_text(const char *text, const char *name, json_object *parent)
{
    json_object *obj;

    if (!text) {
        return;
    }

    obj = json_object_new_string(text);
    json_object_object_add(parent, name, obj);
}

static void
node_metadata_restr(struct lys_restr *restr, const char *name, json_object *parent)
{
    json_object *obj;

    if (!restr) {
        return;
    }

    obj = json_object_new_string(restr->expr);
    json_object_object_add(parent, name, obj);
}

static void
node_metadata_must(uint8_t must_size, struct lys_restr *must, json_object *parent)
{
    uint8_t i;
    json_object *array, *obj;

    if (!must_size || !must) {
        return;
    }

    array = json_object_new_array();

    for (i = 0; i < must_size; ++i) {
        obj = json_object_new_string(must[i].expr);
        json_object_array_add(array, obj);
    }

    json_object_object_add(parent, "must", array);
}

static void
node_metadata_basic(struct lys_node *node, json_object *parent)
{
    json_object *obj;

    /* description */
    node_metadata_text(node->dsc, "description", parent);

    /* reference */
    node_metadata_text(node->ref, "reference", parent);

    /* config */
    if (node->flags & LYS_CONFIG_R) {
        obj = json_object_new_boolean(0);
    } else {
        obj = json_object_new_boolean(1);
    }
    json_object_object_add(parent, "config", obj);

    /* status */
    if (node->flags & LYS_STATUS_DEPRC) {
        obj = json_object_new_string("deprecated");
    } else if (node->flags & LYS_STATUS_OBSLT) {
        obj = json_object_new_string("obsolete");
    } else {
        obj = json_object_new_string("current");
    }
    json_object_object_add(parent, "status", obj);

    /* mandatory */
    if (node->flags & LYS_MAND_TRUE) {
        obj = json_object_new_boolean(1);
    } else {
        obj = json_object_new_boolean(0);
    }
    json_object_object_add(parent, "mandatory", obj);

    /* NACM extensions */
    if (node->nacm) {
        if (node->nacm & LYS_NACM_DENYW) {
            obj = json_object_new_string("default-deny-write");
        } else {
            obj = json_object_new_string("default-deny-all");
        }
        json_object_object_add(parent, "ext", obj);
    }
}

static void
node_metadata_when(struct lys_when *when, json_object *parent)
{
    json_object *obj;

    if (!when) {
        return;
    }

    obj = json_object_new_string(when->cond);
    json_object_object_add(parent, "when", obj);
}

static void
node_metadata_children_recursive(struct lys_node *node, json_object **child_array, json_object **choice_array)
{
    json_object *obj;
    struct lys_node *child;

    if (!node->child) {
        return;
    }

    LY_TREE_FOR(node->child, child) {
        if (child->nodetype == LYS_USES) {
            node_metadata_children_recursive(child, child_array, choice_array);
        } else if (child->nodetype & (LYS_CONTAINER | LYS_LEAF | LYS_LEAFLIST | LYS_LIST | LYS_ANYXML)) {
            obj = json_object_new_string(child->name);
            if (!*child_array) {
                *child_array = json_object_new_array();
            }
            json_object_array_add(*child_array, obj);
        } else if (child->nodetype == LYS_CHOICE) {
            obj = json_object_new_string(child->name);
            if (!*choice_array) {
                *choice_array = json_object_new_array();
            }
            json_object_array_add(*choice_array, obj);
        }
    }
}

static void
node_metadata_cases_recursive(struct lys_node_choice *choice, json_object *array)
{
    json_object *obj;
    struct lys_node *child;

    if (!choice->child) {
        return;
    }

    LY_TREE_FOR(choice->child, child) {
        if (child->nodetype == LYS_USES) {
            node_metadata_cases_recursive((struct lys_node_choice *)child, array);
        } else if (child->nodetype & (LYS_CONTAINER | LYS_LEAF | LYS_LEAFLIST | LYS_LIST | LYS_ANYXML | LYS_CASE)) {
            obj = json_object_new_string(child->name);
            json_object_array_add(array, obj);
        }
    }
}

static void
node_metadata_min_max(uint32_t min, uint32_t max, json_object *parent)
{
    json_object *obj;

    if (min) {
        obj = json_object_new_int(min);
        json_object_object_add(parent, "min-elements", obj);
    }

    if (max) {
        obj = json_object_new_int(max);
        json_object_object_add(parent, "max-elements", obj);
    }
}

static void
node_metadata_ident_recursive(struct lys_ident *ident, json_object *array)
{
    struct lys_ident_der *cur;
    json_object *obj;

    if (!ident) {
        return;
    }

    obj = json_object_new_string(ident->name);
    json_object_array_add(array, obj);

    for (cur = ident->der; cur; cur = cur->next) {
        node_metadata_ident_recursive(cur->ident, array);
    }
}

static void
node_metadata_type(struct lys_type *type, struct lys_module *module, json_object *parent)
{
    json_object *obj, *array, *item;
    char *str;
    int i;

    /* built-in YANG type */
    if (!type->der->module) {
        switch (type->base) {
        case LY_TYPE_BINARY:
            node_metadata_text("binary", "type", parent);
            node_metadata_restr(type->info.binary.length, "length", parent);
            break;
        case LY_TYPE_BITS:
            node_metadata_text("bits", "type", parent);

            array = json_object_new_array();
            for (i = 0; i < type->info.bits.count; ++i) {
                item = json_object_new_object();
                obj = json_object_new_string(type->info.bits.bit[i].name);
                json_object_object_add(item, "name", obj);
                obj = json_object_new_int(type->info.bits.bit[i].pos);
                json_object_object_add(item, "position", obj);
                json_object_array_add(array, item);
            }
            json_object_object_add(parent, "bits", array);
            break;
        case LY_TYPE_BOOL:
            node_metadata_text("bool", "type", parent);
            break;
        case LY_TYPE_DEC64:
            node_metadata_text("decimal64", "type", parent);
            node_metadata_restr(type->info.dec64.range, "range", parent);
            obj = json_object_new_int(type->info.dec64.dig);
            json_object_object_add(parent, "fraction-digits", obj);
            break;
        case LY_TYPE_EMPTY:
            node_metadata_text("empty", "type", parent);
            break;
        case LY_TYPE_ENUM:
            node_metadata_text("enumeration", "type", parent);

            array = json_object_new_array();
            for (i = 0; i < type->info.enums.count; ++i) {
                obj = json_object_new_string(type->info.enums.enm[i].name);
                json_object_array_add(array, obj);
            }
            json_object_object_add(parent, "enumval", array);
            break;
        case LY_TYPE_IDENT:
            node_metadata_text("identityref", "type", parent);

            array = json_object_new_array();
            node_metadata_ident_recursive(type->info.ident.ref, array);
            json_object_object_add(parent, "identityval", array);
            break;
        case LY_TYPE_INST:
            node_metadata_text("instance-identifier", "type", parent);
            if (type->info.inst.req == -1) {
                obj = json_object_new_boolean(0);
            } else {
                obj = json_object_new_boolean(1);
            }
            json_object_object_add(parent, "require-instance", obj);
            break;
        case LY_TYPE_LEAFREF:
            node_metadata_text("leafref", "type", parent);
            node_metadata_text(type->info.lref.path, "path", parent);
            break;
        case LY_TYPE_STRING:
            node_metadata_text("string", "type", parent);
            node_metadata_restr(type->info.str.length, "length", parent);
            if (type->info.str.pat_count) {
                array = json_object_new_array();
                for (i = 0; i < type->info.str.pat_count; ++i) {
                    obj = json_object_new_string(type->info.str.patterns[i].expr);
                    json_object_array_add(array, obj);
                }
                json_object_object_add(parent, "pattern", array);
            }
            break;
        case LY_TYPE_UNION:
            node_metadata_text("union", "type", parent);
            array = json_object_new_array();
            for (i = 0; i < type->info.uni.count; ++i) {
                obj = json_object_new_object();
                node_metadata_type(&type->info.uni.types[i], module, obj);
                json_object_array_add(array, obj);
            }
            json_object_object_add(parent, "types", array);
            break;
        case LY_TYPE_INT8:
            node_metadata_text("int8", "type", parent);
            node_metadata_restr(type->info.num.range, "range", parent);
            break;
        case LY_TYPE_UINT8:
            node_metadata_text("uint8", "type", parent);
            node_metadata_restr(type->info.num.range, "range", parent);
            break;
        case LY_TYPE_INT16:
            node_metadata_text("int16", "type", parent);
            node_metadata_restr(type->info.num.range, "range", parent);
            break;
        case LY_TYPE_UINT16:
            node_metadata_text("uint16", "type", parent);
            node_metadata_restr(type->info.num.range, "range", parent);
            break;
        case LY_TYPE_INT32:
            node_metadata_text("int32", "type", parent);
            node_metadata_restr(type->info.num.range, "range", parent);
            break;
        case LY_TYPE_UINT32:
            node_metadata_text("uint32", "type", parent);
            node_metadata_restr(type->info.num.range, "range", parent);
            break;
        case LY_TYPE_INT64:
            node_metadata_text("int64", "type", parent);
            node_metadata_restr(type->info.num.range, "range", parent);
            break;
        case LY_TYPE_UINT64:
            node_metadata_text("uint64", "type", parent);
            node_metadata_restr(type->info.num.range, "range", parent);
            break;
        default:
            ERROR("Internal: unknown type (%s:%d)", __FILE__, __LINE__);
            break;
        }

    /* typedef */
    } else {
        if (!module || !type->module_name || !strcmp(type->module_name, module->name)) {
            node_metadata_text(type->der->name, "type", parent);
        } else {
            asprintf(&str, "%s:%s", type->module_name, type->der->name);
            node_metadata_text(str, "type", parent);
            free(str);
        }
        obj = json_object_new_object();
        node_metadata_typedef(type->der, obj);
        json_object_object_add(parent, "typedef", obj);
    }
}

static void
node_metadata_typedef(struct lys_tpdf *tpdf, json_object *parent)
{
    json_object *obj;

    /* description */
    node_metadata_text(tpdf->dsc, "description", parent);

    /* reference */
    node_metadata_text(tpdf->ref, "reference", parent);

    /* status */
    if (tpdf->flags & LYS_STATUS_DEPRC) {
        obj = json_object_new_string("deprecated");
    } else if (tpdf->flags & LYS_STATUS_OBSLT) {
        obj = json_object_new_string("obsolete");
    } else {
        obj = json_object_new_string("current");
    }
    json_object_object_add(parent, "status", obj);

    /* type */
    node_metadata_type(&tpdf->type, tpdf->module, parent);

    /* units */
    node_metadata_text(tpdf->units, "units", parent);

    /* default */
    node_metadata_text(tpdf->dflt, "default", parent);
}

static void
node_metadata_container(struct lys_node_container *cont, json_object *parent)
{
    json_object *obj, *child_array = NULL, *choice_array = NULL;

    /* element type */
    obj = json_object_new_string("container");
    json_object_object_add(parent, "eltype", obj);

    /* shared info */
    node_metadata_basic((struct lys_node *)cont, parent);

    /* must */
    node_metadata_must(cont->must_size, cont->must, parent);

    /* presence */
    node_metadata_text(cont->presence, "presence", parent);

    /* when */
    node_metadata_when(cont->when, parent);

    /* children & choice */
    node_metadata_children_recursive((struct lys_node *)cont, &child_array, &choice_array);
    if (child_array) {
        json_object_object_add(parent, "children", child_array);
    }
    if (choice_array) {
        json_object_object_add(parent, "choice", choice_array);
    }
}

static void
node_metadata_choice(struct lys_node_choice *choice, json_object *parent)
{
    json_object *obj, *array;

    /* element type */
    obj = json_object_new_string("choice");
    json_object_object_add(parent, "eltype", obj);

    /* shared info */
    node_metadata_basic((struct lys_node *)choice, parent);

    /* default */
    if (choice->dflt) {
        node_metadata_text(choice->dflt->name, "default", parent);
    }

    /* when */
    node_metadata_when(choice->when, parent);

    /* cases */
    if (choice->child) {
        array = json_object_new_array();
        node_metadata_cases_recursive(choice, array);
        json_object_object_add(parent, "cases", array);
    }
}

static void
node_metadata_leaf(struct lys_node_leaf *leaf, json_object *parent)
{
    json_object *obj;
    struct lys_node_list *list;
    int is_key, i;

    /* element type */
    obj = json_object_new_string("leaf");
    json_object_object_add(parent, "eltype", obj);

    /* shared info */
    node_metadata_basic((struct lys_node *)leaf, parent);

    /* type */
    node_metadata_type(&leaf->type, leaf->module, parent);

    /* units */
    node_metadata_text(leaf->units, "units", parent);

    /* default */
    node_metadata_text(leaf->dflt, "default", parent);

    /* must */
    node_metadata_must(leaf->must_size, leaf->must, parent);

    /* when */
    node_metadata_when(leaf->when, parent);

    /* iskey */
    is_key = 0;
    list = (struct lys_node_list *)lys_parent((struct lys_node *)leaf);
    if (list && (list->nodetype == LYS_LIST)) {
        for (i = 0; i < list->keys_size; ++i) {
            if (list->keys[i] == leaf) {
                is_key = 1;
                break;
            }
        }
    }
    obj = json_object_new_boolean(is_key);
    json_object_object_add(parent, "iskey", obj);
}

static void
node_metadata_leaflist(struct lys_node_leaflist *llist, json_object *parent)
{
    json_object *obj;

    /* element type */
    obj = json_object_new_string("leaf-list");
    json_object_object_add(parent, "eltype", obj);

    /* shared info */
    node_metadata_basic((struct lys_node *)llist, parent);

    /* type */
    node_metadata_type(&llist->type, llist->module, parent);

    /* units */
    node_metadata_text(llist->units, "units", parent);

    /* must */
    node_metadata_must(llist->must_size, llist->must, parent);

    /* when */
    node_metadata_when(llist->when, parent);

    /* min/max-elements */
    node_metadata_min_max(llist->min, llist->max, parent);
}

static void
node_metadata_list(struct lys_node_list *list, json_object *parent)
{
    json_object *obj, *array, *child_array = NULL, *choice_array = NULL;;
    int i;
    unsigned int j;

    /* element type */
    obj = json_object_new_string("list");
    json_object_object_add(parent, "eltype", obj);

    /* shared info */
    node_metadata_basic((struct lys_node *)list, parent);

    /* must */
    node_metadata_must(list->must_size, list->must, parent);

    /* when */
    node_metadata_when(list->when, parent);

    /* min/max-elements */
    node_metadata_min_max(list->min, list->max, parent);

    /* keys */
    if (list->keys_size) {
        array = json_object_new_array();
        for (i = 0; i < list->keys_size; ++i) {
            obj = json_object_new_string(list->keys[i]->name);
            json_object_array_add(array, obj);
        }
        json_object_object_add(parent, "keys", array);
    }

    /* unique */
    if (list->unique_size) {
        array = json_object_new_array();
        for (i = 0; i < list->unique_size; ++i) {
            for (j = 0; j < list->unique[i].expr_size; ++j) {
                obj = json_object_new_string(list->unique[i].expr[j]);
                json_object_array_add(array, obj);
            }
        }
        json_object_object_add(parent, "unique", array);
    }

    /* children & choice */
    node_metadata_children_recursive((struct lys_node *)list, &child_array, &choice_array);
    if (child_array) {
        json_object_object_add(parent, "children", child_array);
    }
    if (choice_array) {
        json_object_object_add(parent, "choice", choice_array);
    }
}

static void
node_metadata_anyxml(struct lys_node_anyxml *anyxml, json_object *parent)
{
    json_object *obj;

    /* element type */
    obj = json_object_new_string("anyxml");
    json_object_object_add(parent, "eltype", obj);

    /* shared info */
    node_metadata_basic((struct lys_node *)anyxml, parent);

    /* must */
    node_metadata_must(anyxml->must_size, anyxml->must, parent);

    /* when */
    node_metadata_when(anyxml->when, parent);

}

static void
node_metadata_case(struct lys_node_case *cas, json_object *parent)
{
    json_object *obj;

    /* element type */
    obj = json_object_new_string("case");
    json_object_object_add(parent, "eltype", obj);

    /* shared info */
    node_metadata_basic((struct lys_node *)cas, parent);

    /* when */
    node_metadata_when(cas->when, parent);
}

static void
node_metadata_rpc(struct lys_node_rpc *rpc, json_object *parent)
{
    json_object *obj;

    /* element type */
    obj = json_object_new_string("rpc");
    json_object_object_add(parent, "eltype", obj);

    /* description */
    node_metadata_text(rpc->dsc, "description", parent);

    /* reference */
    node_metadata_text(rpc->ref, "reference", parent);

    /* status */
    if (rpc->flags & LYS_STATUS_DEPRC) {
        obj = json_object_new_string("deprecated");
    } else if (rpc->flags & LYS_STATUS_OBSLT) {
        obj = json_object_new_string("obsolete");
    } else {
        obj = json_object_new_string("current");
    }
    json_object_object_add(parent, "status", obj);
}

static void
node_metadata_model(const struct lys_module *module, json_object *parent)
{
    json_object *obj, *array, *item;
    const struct lys_node *node;
    int i;

    /* yang-version */
    if (module->version == 2) {
        obj = json_object_new_string("1.1");
    } else {
        obj = json_object_new_string("1.0");
    }
    json_object_object_add(parent, "yang-version", obj);

    /* namespace */
    node_metadata_text(module->ns, "namespace", parent);

    /* prefix */
    node_metadata_text(module->prefix, "prefix", parent);

    /* contact */
    node_metadata_text(module->contact, "contact", parent);

    /* organization */
    node_metadata_text(module->org, "organization", parent);

    /* revision */
    if (module->rev_size) {
        node_metadata_text(module->rev[0].date, "revision", parent);
    }

    /* description */
    node_metadata_text(module->dsc, "description", parent);

    /* import */
    if (module->imp_size) {
        array = json_object_new_array();
        for (i = 0; i < module->imp_size; ++i) {
            item = json_object_new_object();

            node_metadata_text(module->imp[i].module->name, "name", item);
            node_metadata_text(module->imp[i].prefix, "prefix", item);
            if (module->imp[i].rev && module->imp[i].rev[0]) {
                node_metadata_text(module->imp[i].rev, "revision", item);
            }

            json_object_array_add(array, item);
        }
        json_object_object_add(parent, "imports", array);
    }

    /* include */
    if (module->inc_size) {
        array = json_object_new_array();
        for (i = 0; i < module->inc_size; ++i) {
            item = json_object_new_object();

            node_metadata_text(module->inc[i].submodule->name, "name", item);
            if (module->inc[i].rev && module->inc[i].rev[0]) {
                node_metadata_text(module->inc[i].rev, "revision", item);
            }

            json_object_array_add(array, item);
        }
        json_object_object_add(parent, "includes", array);
    }

    /* top-nodes */
    node = NULL;
    array = NULL;
    while ((node = lys_getnext(node, NULL, module, LYS_GETNEXT_WITHCHOICE))) {
        if (node->nodetype & (LYS_RPC | LYS_NOTIF)) {
            continue;
        }
        if (!array) {
            array = json_object_new_array();
        }
        item = json_object_new_string(node->name);
        json_object_array_add(array, item);
    }
    if (array) {
        json_object_object_add(parent, "top-nodes", array);
    }
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
 * \return NC_MSG_WOULDBLOCK or NC_MSG_ERROR.
 * On success, it returns NC_MSG_REPLY.
 */
NC_MSG_TYPE
netconf_send_recv_timed(struct nc_session *session, struct nc_rpc *rpc, int timeout, int strict, struct nc_reply **reply)
{
    uint64_t msgid;
    NC_MSG_TYPE ret;
    ret = nc_send_rpc(session, rpc, timeout, &msgid);
    if (ret != NC_MSG_RPC) {
        return ret;
    }

    while ((ret = nc_recv_reply(session, rpc, msgid, timeout, (strict ? LYD_OPT_STRICT : 0), reply)) == NC_MSG_NOTIF);

    return ret;
}

/**
 * \brief Connect to NETCONF server
 *
 * \warning Session_key hash is not bound with caller identification. This could be potential security risk.
 */
static unsigned int
netconf_connect(const char *host, const char *port, const char *user, const char *pass, const char *privkey)
{
    struct nc_session* session = NULL;
    struct session_with_mutex *locked_session, *last_session;
    char *pubkey;

    /* connect to the requested NETCONF server */
    password = (char*)pass;
    if (privkey) {
        nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, 3);
        asprintf(&pubkey, "%s.pub", privkey);
        nc_client_ssh_add_keypair(pubkey, privkey);
        free(pubkey);
    }
    nc_client_ssh_set_username(user);
    DEBUG("prepare to connect %s@%s:%s", user, host, port);
    session = nc_connect_ssh(host, (unsigned short)atoi(port), NULL);
    DEBUG("nc_session_connect done");

    /* if connected successful, add session to the list */
    if (session != NULL) {
        if ((locked_session = calloc(1, sizeof(struct session_with_mutex))) == NULL || pthread_mutex_init (&locked_session->lock, NULL) != 0) {
            nc_session_free(session, NULL);
            session = NULL;
            free(locked_session);
            locked_session = NULL;
            ERROR("Creating structure session_with_mutex failed %d (%s)", errno, strerror(errno));
            return 0;
        }
        locked_session->session = session;
        locked_session->hello_message = NULL;
        locked_session->closed = 0;
        pthread_mutex_init(&locked_session->lock, NULL);
        DEBUG("Before session_lock");
        /* get exclusive access to sessions_list (conns) */
        DEBUG("LOCK wrlock %s", __func__);
        if (pthread_rwlock_wrlock(&session_lock) != 0) {
            nc_session_free(session, NULL);
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
        session_user_activity(nc_session_get_username(locked_session->session));

        /* no need to lock session, noone can read it while we have wrlock */

        /* store information about session from hello message for future usage */
        prepare_status_message(locked_session, session);

        DEBUG("NETCONF session established");
        locked_session->session_key = session_key_generator;
        ++session_key_generator;
        if (session_key_generator == UINT_MAX) {
            session_key_generator = 1;
        }

        DEBUG("Before session_unlock");
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
    int i;

    DEBUG("LOCK mutex %s", __func__);
    if (pthread_mutex_lock(&locked_session->lock) != 0) {
        ERROR("Error while locking rwlock");
    }
    locked_session->ntfc_subscribed = 0;
    locked_session->closed = 1;
    if (locked_session->session != NULL) {
        nc_session_free(locked_session->session, NULL);
        locked_session->session = NULL;
    }
    DEBUG("session closed.");
    DEBUG("UNLOCK mutex %s", __func__);
    if (pthread_mutex_unlock(&locked_session->lock) != 0) {
        ERROR("Error while locking rwlock");
    }

    DEBUG("closed session, disabled notif(?), wait 0.5s");
    usleep(500000); /* let notification thread stop */

    /* session shouldn't be used by now */
    for (i = 0; i < locked_session->notif_count; ++i) {
        free(locked_session->notifications[i].content);
    }
    free(locked_session->notifications);
    pthread_mutex_destroy(&locked_session->lock);
    if (locked_session->hello_message != NULL) {
        json_object_put(locked_session->hello_message);
        locked_session->hello_message = NULL;
    }
    locked_session->session = NULL;
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
    DEBUG("LOCK wrlock %s", __func__);
    if (pthread_rwlock_wrlock(&session_lock) != 0) {
        ERROR("Error while locking rwlock");
        (*reply) = create_error_reply("Internal: Error while locking.");
        return EXIT_FAILURE;
    }
    /* remove session from the active sessions list -> nobody new can now work with session */
    for (locked_session = netconf_sessions_list;
         locked_session && (locked_session->session_key != session_key);
         locked_session = locked_session->next);

    if (!locked_session) {
        DEBUG("UNLOCK wrlock %s", __func__);
        pthread_rwlock_unlock(&session_lock);
        ERROR("Could not find the session %u to close.", session_key);
        (*reply) = create_error_reply("Internal: Error while finding a session.");
        return EXIT_FAILURE;
    }

    if (!locked_session->prev) {
        netconf_sessions_list = netconf_sessions_list->next;
        if (netconf_sessions_list) {
            netconf_sessions_list->prev = NULL;
        }
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
netconf_test_reply(struct nc_session *session, unsigned int session_key, NC_MSG_TYPE msgt, struct nc_reply *reply, struct lyd_node **data)
{
    json_object *err = NULL;

    /* process the result of the operation */
    switch (msgt) {
        case NC_MSG_ERROR:
            if (nc_session_get_status(session) != NC_STATUS_RUNNING) {
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
            switch (reply->type) {
                case NC_RPL_OK:
                    if ((data != NULL) && (*data != NULL)) {
                        free(*data);
                        (*data) = NULL;
                    }
                    return create_ok_reply();
                case NC_RPL_DATA:
                    if (((*data) = ((struct nc_reply_data *)reply)->data) == NULL) {
                        ERROR("mod_netconf: no data from reply");
                        return create_error_reply("Internal: No data from reply received.");
                    } else {
                        ((struct nc_reply_data *)reply)->data = NULL;
                        return NULL;
                    }
                    break;
                case NC_RPL_ERROR:
                    ERROR("mod_netconf: unexpected rpc-reply (%d)", reply->type);
                    if (data != NULL) {
                        free(*data);
                        (*data) = NULL;
                    }
                    return create_error_reply(((struct nc_reply_error *)reply)->err[0].message);
                default:
                    ERROR("mod_netconf: unexpected rpc-reply (%d)", reply->type);
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
netconf_unlocked_op(struct nc_session *session, struct nc_rpc *rpc)
{
    struct nc_reply* reply = NULL;
    NC_MSG_TYPE msgt;

    /* check requests */
    if (rpc == NULL) {
        ERROR("mod_netconf: rpc is not created");
        return create_error_reply("Internal error: RPC is not created");
    }

    if (session != NULL) {
        /* send the request and get the reply */
        msgt = netconf_send_recv_timed(session, rpc, 50000, 0, &reply);
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
netconf_op(unsigned int session_key, struct nc_rpc *rpc, int strict, struct lyd_node **received_data)
{
    struct session_with_mutex * locked_session;
    struct nc_reply* reply = NULL;
    json_object *res = NULL;
    struct lyd_node *data = NULL;
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

    session_user_activity(nc_session_get_username(locked_session->session));

    /* send the request and get the reply */
    msgt = netconf_send_recv_timed(locked_session->session, rpc, 2000000, strict, &reply);

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
    struct nc_rpc* rpc;
    struct session_with_mutex *locked_session;
    json_object *res = NULL, *data_cjson;
    enum json_tokener_error tok_err;
    char *data_json = NULL;
    struct lyd_node *data, *sibling, *next;

    /* tell server to show all elements even if they have default values */
#ifdef HAVE_WITHDEFAULTS_TAGGED
    rpc = nc_rpc_getconfig(source, filter, NC_WD_MODE_ALL_TAG, NC_PARAMTYPE_CONST);
#else
    rpc = nc_rpc_getconfig(source, filter, 0, NC_PARAMTYPE_CONST);
#endif
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return (NULL);
    }

    res = netconf_op(session_key, rpc, strict, &data);
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

        /* print data into JSON */
        if (lyd_print_mem(&data_json, data, LYD_JSON, LYP_WITHSIBLINGS)) {
            ERROR("Printing JSON <get-config> data failed.");
            lyd_free_withsiblings(data);
            return NULL;
        }

        /* parse JSON data into cjson */
        pthread_mutex_lock(&json_lock);
        data_cjson = json_tokener_parse_verbose(data_json, &tok_err);
        if (!data_cjson) {
            ERROR("Parsing JSON config failed (%s).", json_tokener_error_desc(tok_err));
            pthread_mutex_unlock(&json_lock);
            lyd_free_withsiblings(data);
            free(data_json);
            return NULL;
        }
        free(data_json);

        /* go simultaneously through both trees and add metadata */
        LY_TREE_FOR_SAFE(data, next, sibling) {
            node_add_metadata_recursive(sibling, NULL, data_cjson);
            lyd_free(sibling);
        }

        data_json = strdup(json_object_to_json_string_ext(data_cjson, 0));
        json_object_put(data_cjson);
        pthread_mutex_unlock(&json_lock);
    }

    return (data_json);
}

static char *
netconf_getschema(unsigned int session_key, const char *identifier, const char *version, const char *format, json_object **err)
{
    struct nc_rpc *rpc;
    struct lyd_node *data = NULL;
    json_object *res = NULL;
    char *model_data = NULL;

    /* create requests */
    rpc = nc_rpc_getschema(identifier, version, format, NC_PARAMTYPE_CONST);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return (NULL);
    }

    res = netconf_op(session_key, rpc, 0, &data);
    nc_rpc_free(rpc);
    if (res != NULL) {
        (*err) = res;
    } else {
        (*err) = NULL;

        if (data) {
            if (((struct lyd_node_anyxml *)data)->xml_struct) {
                lyxml_print_mem(&model_data, ((struct lyd_node_anyxml *)data)->value.xml, 0);
            } else {
                model_data = strdup(((struct lyd_node_anyxml *)data)->value.str);
            }
            if (!model_data) {
                ERROR("memory allocation fail (%s:%d)", __FILE__, __LINE__);
            }
        }
    }

    return (model_data);
}

static char *
netconf_get(unsigned int session_key, const char* filter, int strict, json_object **err)
{
    struct nc_rpc* rpc;
    char* data_json = NULL;
    json_object *res = NULL, *data_cjson;
    enum json_tokener_error tok_err;
    struct session_with_mutex *locked_session;
    struct lyd_node *data, *sibling, *next;

    /* create requests */
    rpc = nc_rpc_get(filter, 0, NC_PARAMTYPE_CONST);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return (NULL);
    }

    res = netconf_op(session_key, rpc, strict, &data);
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

        /* print JSON data */
        if (lyd_print_mem(&data_json, data, LYD_JSON, LYP_WITHSIBLINGS)) {
            ERROR("Printing JSON <get> data failed.");
            lyd_free_withsiblings(data);
            return NULL;
        }

        /* parse JSON data into cjson */
        pthread_mutex_lock(&json_lock);
        data_cjson = json_tokener_parse_verbose(data_json, &tok_err);
        if (!data_cjson) {
            ERROR("Parsing JSON config failed (%s).", json_tokener_error_desc(tok_err));
            pthread_mutex_unlock(&json_lock);
            lyd_free_withsiblings(data);
            free(data_json);
            return NULL;
        }
        free(data_json);

        /* go simultaneously through both trees and add metadata */
        LY_TREE_FOR_SAFE(data, next, sibling) {
            node_add_metadata_recursive(sibling, NULL, data_cjson);
            lyd_free(sibling);
        }

        data_json = strdup(json_object_to_json_string_ext(data_cjson, 0));
        json_object_put(data_cjson);
        pthread_mutex_unlock(&json_lock);
    }

    return data_json;
}

static json_object *
netconf_copyconfig(unsigned int session_key, NC_DATASTORE source, NC_DATASTORE target, const char *config,
                   const char *uri_src, const char *uri_trg)
{
    struct nc_rpc* rpc;
    json_object *res = NULL;

    /* create requests */
    rpc = nc_rpc_copy(target, uri_trg, source, (config ? config : uri_src), 0, NC_PARAMTYPE_CONST);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, 0, NULL);
    nc_rpc_free(rpc);

    return res;
}

static json_object *
netconf_editconfig(unsigned int session_key, NC_DATASTORE target, NC_RPC_EDIT_DFLTOP defop,
                   NC_RPC_EDIT_ERROPT erropt, NC_RPC_EDIT_TESTOPT testopt, const char *config_or_url)
{
    struct nc_rpc* rpc;
    json_object *res = NULL;

    /* create requests */
    rpc = nc_rpc_edit(target, defop, testopt, erropt, config_or_url, NC_PARAMTYPE_CONST);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, 0, NULL);
    nc_rpc_free (rpc);

    return res;
}

static json_object *
netconf_killsession(unsigned int session_key, const char *sid)
{
    struct nc_rpc *rpc;
    json_object *res = NULL;

    /* create requests */
    rpc = nc_rpc_kill(atoi(sid));
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, 0, NULL);
    nc_rpc_free(rpc);
    return res;
}

static json_object *
netconf_onlytargetop(unsigned int session_key, NC_DATASTORE target, struct nc_rpc *(*op_func)(NC_DATASTORE))
{
    struct nc_rpc* rpc;
    json_object *res = NULL;

    /* create requests */
    rpc = op_func(target);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, 0, NULL);
    nc_rpc_free (rpc);
    return res;
}

static json_object *
netconf_deleteconfig(unsigned int session_key, NC_DATASTORE target, const char *url)
{
    struct nc_rpc *rpc = NULL;
    json_object *res = NULL;
    rpc = nc_rpc_delete(target, url, NC_PARAMTYPE_CONST);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    res = netconf_op(session_key, rpc, 0, NULL);
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
netconf_generic(unsigned int session_key, const char *xml_content, struct lyd_node **data)
{
    struct nc_rpc* rpc = NULL;
    json_object *res = NULL;

    /* create requests */
    rpc = nc_rpc_generic_xml(xml_content, NC_PARAMTYPE_CONST);
    if (rpc == NULL) {
        ERROR("mod_netconf: creating rpc request failed");
        return create_error_reply("Internal: Creating rpc request failed");
    }

    /* get session where send the RPC */
    res = netconf_op(session_key, rpc, 0, data);
    nc_rpc_free(rpc);
    return res;
}

static int
node_add_metadata(const struct lys_node *node, const struct lys_module *module, json_object *parent)
{
    struct lys_module *cur_module;
    json_object *meta_obj;
    char *obj_name;

    if (node->nodetype == LYS_INPUT) {
        /* silently skipped */
        return 0;
    }

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
    if ((node->nodetype & (LYS_LEAFLIST | LYS_LIST)) && (json_object_object_get_ex(parent, obj_name, NULL) == TRUE)) {
        free(obj_name);
        return 1;
    }

    meta_obj = json_object_new_object();

    switch (node->nodetype) {
        case LYS_CONTAINER:
            node_metadata_container((struct lys_node_container *)node, meta_obj);
            break;
        case LYS_CHOICE:
            node_metadata_choice((struct lys_node_choice *)node, meta_obj);
            break;
        case LYS_LEAF:
            node_metadata_leaf((struct lys_node_leaf *)node, meta_obj);
            break;
        case LYS_LEAFLIST:
            node_metadata_leaflist((struct lys_node_leaflist *)node, meta_obj);
            break;
        case LYS_LIST:
            node_metadata_list((struct lys_node_list *)node, meta_obj);
            break;
        case LYS_ANYXML:
            node_metadata_anyxml((struct lys_node_anyxml *)node, meta_obj);
            break;
        case LYS_CASE:
            node_metadata_case((struct lys_node_case *)node, meta_obj);
            break;
        case LYS_RPC:
            node_metadata_rpc((struct lys_node_rpc *)node, meta_obj);
            break;
        default: /* LYS_OUTPUT */
            ERROR("Internal: unuxpected nodetype (%s:%d)", __FILE__, __LINE__);
            break;
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
node_add_metadata_recursive(struct lyd_node *data_tree, const struct lys_module *module, json_object *data_json_parent)
{
    struct lys_module *cur_module;
    struct lys_node *list_schema;
    struct lyd_node *child, *list_item;
    json_object *child_json, *list_child_json;
    char *child_name;
    int list_idx;

    if (data_tree->schema->nodetype & (LYS_OUTPUT | LYS_GROUPING)) {
        return;
    }

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
node_add_model_metadata(const struct lys_module *module, json_object *parent)
{
    json_object *obj;
    char *str;

    obj = json_object_new_object();
    node_metadata_model(module, obj);
    asprintf(&str, "$@@%s", module->name);
    json_object_object_add(parent, str, obj);
    free(str);
}

static void
node_add_children_with_metadata_recursive(const struct lys_node *node, const struct lys_module *module, json_object *parent)
{
    const struct lys_module *cur_module;
    struct lys_node *child;
    json_object *node_json;
    char *json_name;

    if (node->nodetype & (LYS_OUTPUT | LYS_GROUPING)) {
        return;
    }

    if (node->nodetype & LYS_USES) {
        cur_module = module;
        node_json = parent;
        goto children;
    }

    /* add node metadata */
    if (node_add_metadata(node, module, parent)) {
        ERROR("Internal: metadata duplicate for \"%s\".", node->name);
        return;
    }

    /* no other metadata */
    if (!node->child) {
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

children:
    if (!(node->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML))) {
        LY_TREE_FOR(node->child, child) {
            node_add_children_with_metadata_recursive(child, cur_module, node_json);
        }
    }
}

static json_object *
libyang_query(unsigned int session_key, const char *filter, int load_children)
{
    const struct lys_node *node;
    const struct lys_module *module = NULL;
    struct session_with_mutex *locked_session;
    json_object *ret = NULL, *data;

    locked_session = session_get_locked(session_key, &ret);
    if (!locked_session) {
        ERROR("Locking failed or session not found.");
        goto finish;
    }

    session_user_activity(nc_session_get_username(locked_session->session));

    if (filter[0] == '/') {
        node = ly_ctx_get_node(nc_session_get_ctx(locked_session->session), NULL, filter);
        if (!node) {
            ret = create_error_reply("Failed to resolve XPath filter node.");
            goto finish;
        }
    } else {
        module = ly_ctx_get_module(nc_session_get_ctx(locked_session->session), filter, NULL);
        if (!module) {
            ret = create_error_reply("Failed to find model.");
            goto finish;
        }
    }

    pthread_mutex_lock(&json_lock);
    data = json_object_new_object();

    if (module) {
        node_add_model_metadata(module, data);
        if (load_children) {
            LY_TREE_FOR(module->data, node) {
                node_add_children_with_metadata_recursive(node, NULL, data);
            }
        }
    } else {
        if (load_children) {
            node_add_children_with_metadata_recursive(node, NULL, data);
        } else {
            node_add_metadata(node, NULL, data);
        }
    }

    pthread_mutex_unlock(&json_lock);
    ret = create_data_reply(json_object_to_json_string(data));
    json_object_put(data);

finish:
    session_unlock(locked_session);
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

    session_user_activity(nc_session_get_username(locked_session->session));

    data_tree = lyd_parse_mem(nc_session_get_ctx(locked_session->session), config, LYD_JSON, LYD_OPT_STRICT);
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
    switch (level) {
    case NC_VERB_ERROR:
        ERROR("lib ERROR: %s", msg);
        break;
    case NC_VERB_WARNING:
        ERROR("lib WARNING: %s", msg);
        break;
    case NC_VERB_VERBOSE:
        ERROR("lib VERBOSE: %s", msg);
        break;
    case NC_VERB_DEBUG:
        DEBUG("lib DEBUG: %s", msg);
        break;
    }

    if (level == NC_VERB_ERROR) {
        /* return global error */
        netconf_callback_error_process(msg);
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

NC_RPC_EDIT_TESTOPT
parse_testopt(const char *t)
{
    if (strcmp(t, "notset") == 0) {
        return NC_RPC_EDIT_TESTOPT_UNKNOWN;
    } else if (strcmp(t, "testset") == 0) {
        return NC_RPC_EDIT_TESTOPT_TESTSET;
    } else if (strcmp(t, "set") == 0) {
        return NC_RPC_EDIT_TESTOPT_SET;
    } else if (strcmp(t, "test") == 0) {
        return NC_RPC_EDIT_TESTOPT_TEST;
    }
    return NC_RPC_EDIT_TESTOPT_UNKNOWN;
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
    json_object *reply;

    pthread_mutex_lock(&json_lock);
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
    char *privkey = NULL;
    json_object *reply = NULL;
    unsigned int session_key = 0;

    DEBUG("Request: connect");
    pthread_mutex_lock(&json_lock);

    host = get_param_string(request, "host");
    port = get_param_string(request, "port");
    user = get_param_string(request, "user");
    pass = get_param_string(request, "pass");
    privkey = get_param_string(request, "privatekey");

    pthread_mutex_unlock(&json_lock);

    if (host == NULL) {
        host = "localhost";
    }

    DEBUG("host: %s, port: %s, user: %s", host, port, user);
    if (user == NULL) {
        ERROR("Cannot connect - insufficient input.");
        session_key = 0;
    } else {
        session_key = netconf_connect(host, port, user, pass, privkey);
        DEBUG("Session key: %u", session_key);
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
    CHECK_AND_FREE(privkey);
    return reply;
}

json_object *
handle_op_disconnect(json_object *UNUSED(request), unsigned int session_key)
{
    json_object *reply = NULL;

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
    NC_DATASTORE ds_type_t = -1;
    NC_RPC_EDIT_DFLTOP defop_type = 0;
    NC_RPC_EDIT_ERROPT erropt_type = 0;
    NC_RPC_EDIT_TESTOPT testopt_type = NC_RPC_EDIT_TESTOPT_TESTSET;
    char *defop = NULL;
    char *erropt = NULL;
    char *config = NULL;
    char *target = NULL;
    char *testopt = NULL;
    char *urisource = NULL;
    json_object *reply = NULL, *configs, *obj;
    struct lyd_node *content;
    struct session_with_mutex *locked_session;

    DEBUG("Request: edit-config (session %u)", session_key);

    pthread_mutex_lock(&json_lock);
    /* get parameters */
    if (json_object_object_get_ex(request, "configs", &configs) == FALSE) {
        pthread_mutex_unlock(&json_lock);
        reply = create_error_reply("Missing configs parameter.");
        goto finalize;
    }
    obj = json_object_array_get_idx(configs, idx);
    config = strdup(json_object_get_string(obj));

    target = get_param_string(request, "target");
    defop = get_param_string(request, "default-operation");
    erropt = get_param_string(request, "error-option");
    urisource = get_param_string(request, "uri-source");
    testopt = get_param_string(request, "test-option");
    pthread_mutex_unlock(&json_lock);

    if (!target) {
        ERROR("Missing the target parameter.");
        goto finalize;
    }
    ds_type_t = parse_datastore(target);

    if (defop != NULL) {
        if (strcmp(defop, "merge") == 0) {
            defop_type = NC_RPC_EDIT_DFLTOP_MERGE;
        } else if (strcmp(defop, "replace") == 0) {
            defop_type = NC_RPC_EDIT_DFLTOP_REPLACE;
        } else if (strcmp(defop, "none") == 0) {
            defop_type = NC_RPC_EDIT_DFLTOP_NONE;
        } else {
            reply = create_error_reply("Invalid default-operation parameter.");
            goto finalize;
        }
    } else {
        defop_type = NC_RPC_EDIT_DFLTOP_UNKNOWN;
    }

    if (erropt != NULL) {
        if (strcmp(erropt, "continue-on-error") == 0) {
            erropt_type = NC_RPC_EDIT_ERROPT_CONTINUE;
        } else if (strcmp(erropt, "stop-on-error") == 0) {
            erropt_type = NC_RPC_EDIT_ERROPT_STOP;
        } else if (strcmp(erropt, "rollback-on-error") == 0) {
            erropt_type = NC_RPC_EDIT_ERROPT_ROLLBACK;
        } else {
            reply = create_error_reply("Invalid error-option parameter.");
            goto finalize;
        }
    } else {
        erropt_type = 0;
    }

    if ((config && urisource) || (!config && !urisource)) {
        reply = create_error_reply("Invalid config and uri-source data parameters.");
        goto finalize;
    }

    if (config) {
        locked_session = session_get_locked(session_key, NULL);
        if (!locked_session) {
            ERROR("Unknown session or locking failed.");
            goto finalize;
        }

        content = lyd_parse_mem(nc_session_get_ctx(locked_session->session), config, LYD_JSON, LYD_OPT_EDIT);
        session_unlock(locked_session);

        if (!content) {
            ERROR("Failed to parse edit-config content.");
            goto finalize;
        }

        free(config);
        config = NULL;

        lyd_print_mem(&config, content, LYD_XML, LYP_WITHSIBLINGS);
        lyd_free_withsiblings(content);
        if (!config) {
            ERROR("Failed to print edit-config content.");
            goto finalize;
        }
    } else {
        config = urisource;
    }

    if (testopt != NULL) {
        testopt_type = parse_testopt(testopt);
    } else {
        testopt_type = NC_RPC_EDIT_TESTOPT_TESTSET;
    }

    reply = netconf_editconfig(session_key, ds_type_t, defop_type, erropt_type, testopt_type, config);

    CHECK_ERR_SET_REPLY

finalize:
    CHECK_AND_FREE(defop);
    CHECK_AND_FREE(erropt);
    CHECK_AND_FREE(config);
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
    struct lyd_node *content;
    struct session_with_mutex *locked_session;

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

    if (config) {
        locked_session = session_get_locked(session_key, NULL);
        if (!locked_session) {
            ERROR("Unknown session or locking failed.");
            goto finalize;
        }

        content = lyd_parse_mem(nc_session_get_ctx(locked_session->session), config, LYD_JSON, LYD_OPT_CONFIG);
        session_unlock(locked_session);

        free(config);
        lyd_print_mem(&config, content, LYD_XML, LYP_WITHSIBLINGS);
        lyd_free_withsiblings(content);
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
    char *content = NULL, *str;
    struct lyd_node *data = NULL, *node_content;
    struct session_with_mutex *locked_session;

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
    content = strdup(json_object_get_string(obj));
    pthread_mutex_unlock(&json_lock);

    locked_session = session_get_locked(session_key, NULL);
    if (!locked_session) {
        ERROR("Unknown session or locking failed.");
        goto finalize;
    }

    node_content = lyd_parse_mem(nc_session_get_ctx(locked_session->session), content, LYD_JSON, LYD_OPT_RPC);
    session_unlock(locked_session);

    free(content);
    lyd_print_mem(&content, node_content, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(node_content);

    reply = netconf_generic(session_key, content, &data);
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
            lyd_print_mem(&str, data, LYD_JSON, LYP_WITHSIBLINGS);
            lyd_free_withsiblings(data);
            reply = create_data_reply(str);
            free(str);
        }
    }

finalize:
    CHECK_AND_FREE(content);
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
        temp_session = nc_connect_ssh_channel(locked_session->session, NULL);
        if (temp_session != NULL) {
            prepare_status_message(locked_session, temp_session);
            DEBUG("closing temporal NC session.");
            nc_session_free(temp_session, NULL);
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
notification_history(struct nc_session *session, const struct nc_notif *notif)
{
    time_t eventtime;
    char *content;
    (void)session;

    eventtime = nc_datetime2time(notif->datetime);

    json_object *notif_history_array = (json_object *)pthread_getspecific(notif_history_key);
    if (notif_history_array == NULL) {
        ERROR("No list of notification history found.");
        return;
    }
    DEBUG("Got notification from history %lu.", (long unsigned)eventtime);
    pthread_mutex_lock(&json_lock);
    json_object *notif_obj = json_object_new_object();
    if (notif_obj == NULL) {
        ERROR("Could not allocate memory for notification (json).");
        goto failed;
    }
    lyd_print_mem(&content, notif->tree, LYD_JSON, 0);

    json_object_object_add(notif_obj, "eventtime", json_object_new_int64(eventtime));
    json_object_object_add(notif_obj, "content", json_object_new_string(content));

    free(content);

    json_object_array_add(notif_history_array, notif_obj);
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
    struct nc_rpc *rpc = NULL;
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
        temp_session = nc_connect_ssh_channel(locked_session->session, NULL);
        if (temp_session != NULL) {
            rpc = nc_rpc_subscribe(NULL, NULL, nc_time2datetime(start, NULL), nc_time2datetime(stop, NULL), NC_PARAMTYPE_CONST);
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
            DEBUG("LOCK ntf mutex %s", __func__);
            pthread_mutex_lock(&ntf_history_lock);
            pthread_mutex_lock(&json_lock);
            json_object *notif_history_array = json_object_new_array();
            pthread_mutex_unlock(&json_lock);
            if (pthread_setspecific(notif_history_key, notif_history_array) != 0) {
                ERROR("notif_history: cannot set thread-specific hash value.");
            }

            nc_recv_notif_dispatch(temp_session, notification_history);

            pthread_mutex_lock(&json_lock);
            reply = json_object_new_object();
            json_object_object_add(reply, "notifications", notif_history_array);
            //json_object_put(notif_history_array);
            pthread_mutex_unlock(&json_lock);

            DEBUG("UNLOCK ntf mutex %s", __func__);
            pthread_mutex_unlock(&ntf_history_lock);
            DEBUG("closing temporal NC session.");
            nc_session_free(temp_session, NULL);
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
    struct nc_rpc *rpc = NULL;
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
    rpc = nc_rpc_validate(target_ds, url, NC_PARAMTYPE_CONST);
    if (rpc == NULL) {
        DEBUG("mod_netconf: creating rpc request failed");
        reply = create_error_reply("Creation of RPC request failed.");
        goto finalize;
    }

    if ((reply = netconf_op(session_key, rpc, 0, NULL)) == NULL) {
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
    struct lyd_node *content;
    struct session_with_mutex *locked_session;

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

    locked_session = session_get_locked(session_key, NULL);
    if (!locked_session) {
        ERROR("Unknown session or locking failed.");
        goto finalize;
    }

    content = lyd_parse_mem(nc_session_get_ctx(locked_session->session), config, LYD_JSON, LYD_OPT_DATA);
    session_unlock(locked_session);

    free(config);
    lyd_print_mem(&config, content, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free_withsiblings(content);

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
    int operation = (-1), count, i, sent;
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

        buffer = get_framed_message(client);
        if (buffer != NULL) {
            DEBUG("Received message:\n%.*s\n", 1024, buffer);
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
                    pthread_mutex_unlock(&json_lock);
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
                reply = NULL;
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

            if (request != NULL) {
                pthread_mutex_lock(&json_lock);
                json_object_put(request);
                pthread_mutex_unlock(&json_lock);
                request = NULL;
            }

send_reply:
            /* send reply to caller */
            if (replies) {
                pthread_mutex_lock(&json_lock);
                msgtext = json_object_to_json_string(replies);
                pthread_mutex_unlock(&json_lock);
                DEBUG("Sending message:\n%.*s\n", 1024, msgtext);
                if (asprintf(&chunked_out_msg, "\n#%d\n%s\n##\n", (int)strlen(msgtext), msgtext) == -1) {
                    if (buffer != NULL) {
                        free(buffer);
                        buffer = NULL;
                    }
                    break;
                }

                i = 0;
                sent = 0;
                count = strlen(chunked_out_msg) + 1;
                while (count && ((i = send(client, chunked_out_msg + sent, count, 0)) != -1)) {
                    sent += i;
                    count -= i;
                }
                if (i == -1) {
                    ERROR("Sending message failed (%s).", strerror(errno));
                }
                pthread_mutex_lock(&json_lock);
                json_object_put(replies);
                pthread_mutex_unlock(&json_lock);
                replies = NULL;

                CHECK_AND_FREE(chunked_out_msg);
                chunked_out_msg = NULL;
                if (buffer) {
                    free(buffer);
                    buffer = NULL;
                }
                clean_err_reply();
            } else {
                ERROR("Reply is NULL, shouldn't be...");
                continue;
            }
        }
    }
    free(arg);
    free_err_reply();
    nc_thread_destroy();

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
    if ((ret = pthread_rwlock_wrlock(&session_lock)) != 0) {
        ERROR("Error while locking rwlock: %d (%s)", ret, strerror(ret));
        return;
    }
    for (next_session = netconf_sessions_list; next_session;) {
        locked_session = next_session;
        next_session = locked_session->next;

        /* close_and_free_session handles locking on its own */
        DEBUG("Closing NETCONF session %u (SID %u).", locked_session->session_key, nc_session_get_id(locked_session->session));
        close_and_free_session(locked_session);
    }
    netconf_sessions_list = NULL;

    /* get exclusive access to sessions_list (conns) */
    DEBUG("UNLOCK wrlock %s", __func__);
    if (pthread_rwlock_unlock(&session_lock) != 0) {
        ERROR("Error while unlocking rwlock: %d (%s)", errno, strerror(errno));
    }
}

static void
check_timeout_and_close(void)
{
    struct session_with_mutex *locked_session = NULL, *next_session;
    time_t current_time = time(NULL);
    int ret;

    /* get exclusive access to sessions_list (conns) */
    //DEBUG("LOCK wrlock %s", __func__);
    if ((ret = pthread_rwlock_wrlock(&session_lock)) != 0) {
        DEBUG("Error while locking rwlock: %d (%s)", ret, strerror(ret));
        return;
    }

    locked_session = netconf_sessions_list;
    while (locked_session) {
        next_session = locked_session->next;

        if (!locked_session->session) {
            continue;
        }
        if ((current_time - locked_session->last_activity) > ACTIVITY_TIMEOUT) {
            DEBUG("Closing NETCONF session %u (SID %u).", locked_session->session_key, nc_session_get_id(locked_session->session));

            /* remove it from the list */
            if (!locked_session->prev) {
                netconf_sessions_list = netconf_sessions_list->next;
                if (netconf_sessions_list) {
                    netconf_sessions_list->prev = NULL;
                }
            } else {
                locked_session->prev->next = locked_session->next;
                if (locked_session->next) {
                    locked_session->next->prev = locked_session->prev;
                }
            }

            /* close_and_free_session handles locking on its own */
            close_and_free_session(locked_session);
        }

        locked_session = next_session;
    }
    //DEBUG("UNLOCK wrlock %s", __func__);
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
    nc_client_init();
    nc_verbosity(NC_VERB_VERBOSE);
    nc_set_print_clb(clb_print);
    nc_client_ssh_set_auth_hostkey_check_clb(netconf_callback_ssh_hostkey_check);
    nc_client_ssh_set_auth_interactive_clb(netconf_callback_sshauth_interactive);
    nc_client_ssh_set_auth_password_clb(netconf_callback_sshauth_password);
    nc_client_ssh_set_auth_privkey_passphrase_clb(netconf_callback_sshauth_passphrase);

    /* disable publickey authentication */
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, -1);

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

    nc_client_destroy();
    free(ptids);
    close(lsock);
    exit(0);
    return;

error_exit:
    nc_client_destroy();
    close(lsock);
    free(ptids);
    return;
}

int
main(int argc, char **argv)
{
    struct sigaction action;
    sigset_t block_mask;
    int i;

    if (argc > 3) {
        printf("Usage: [--(h)elp] [--(d)aemon] [socket-path]\n");
        return 1;
    }

    sockname = SOCKET_FILENAME;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("Usage: [--(h)elp] [--(d)aemon] [socket-path]\n");
            return 0;
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--daemon")) {
            daemonize = 1;
        } else {
            sockname = argv[i];
        }
    }

    if (daemonize) {
        if (daemon(0, 0) == -1) {
            ERROR("daemon() failed (%s)", strerror(errno));
            return 1;
        }
        openlog("netopeerguid", LOG_PID, LOG_DAEMON);
    }

    sigfillset(&block_mask);
    action.sa_handler = signal_handler;
    action.sa_mask = block_mask;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    forked_proc();
    DEBUG("Terminated");
    if (daemonize) {
        closelog();
    }
    return 0;
}
