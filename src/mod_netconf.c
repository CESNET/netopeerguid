/*!
 * \file mod_netconf.c
 * \brief NETCONF Apache modul for Netopeer
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \date 2011
 * \date 2012
 */
/*
 * Copyright (C) 2011-2012 CESNET
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

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "http_log.h"
#include "apu.h"
#include "apr_general.h"
#include "apr_sha1.h"
#include "apr_file_io.h"

#include <unixd.h>
#include <apr_base64.h>
#include <apr_pools.h>
#include <apr_general.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>
#include <apr_signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <json/json.h>

#include <libnetconf.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

#define MAX_PROCS 5
#define SOCKET_FILENAME "/tmp/mod_netconf.sock"
#define MAX_SOCKET_CL 10
#define BUFFER_SIZE 4096

/* sleep in master process for non-blocking socket reading */
#define SLEEP_TIME 200

#ifndef offsetof
#define offsetof(type, member) ((size_t) ((type *) 0)->member)
#endif

struct timeval timeout = { 1, 0 };

typedef enum MSG_TYPE {
	REPLY_OK,
	REPLY_DATA,
	REPLY_ERROR,
	MSG_CONNECT,
	MSG_DISCONNECT,
	MSG_GET,
	MSG_GETCONFIG,
	MSG_EDITCONFIG,
	MSG_COPYCONFIG,
	MSG_DELETECONFIG,
	MSG_LOCK,
	MSG_UNLOCK,
	MSG_KILL
} MSG_TYPE;

#define MSG_OK 0
#define MSG_OPEN  1
#define MSG_DATA  2
#define MSG_CLOSE 3
#define MSG_ERROR 4
#define MSG_UNKNOWN 5

module AP_MODULE_DECLARE_DATA netconf_module;

typedef struct {
	apr_pool_t *pool;
	apr_proc_t *forkproc;
	char* sockname;
} mod_netconf_cfg;

volatile int isterminated = 0;

static char* password;


static void signal_handler(int sign)
{
	switch (sign) {
	case SIGTERM:
		isterminated = 1;
		break;
	}
}

static char* gen_ncsession_hash( const char* hostname, const char* port, const char* sid)
{
	unsigned char hash_raw[APR_SHA1_DIGESTSIZE];
	int i;
	char* hash;

	apr_sha1_ctx_t sha1_ctx;
	apr_sha1_init(&sha1_ctx);
	apr_sha1_update(&sha1_ctx, hostname, strlen(hostname));
	apr_sha1_update(&sha1_ctx, port, strlen(port));
	apr_sha1_update(&sha1_ctx, sid, strlen(sid));
	apr_sha1_final(hash_raw, &sha1_ctx);

	/* convert binary hash into hex string, which is printable */
	hash = malloc(sizeof(char) * ((2*APR_SHA1_DIGESTSIZE)+1));
	for (i = 0; i < APR_SHA1_DIGESTSIZE; i++) {
		snprintf(hash + (2*i), 3, "%02x", hash_raw[i]);
	}
	//hash[2*APR_SHA1_DIGESTSIZE] = 0;

	return (hash);
}

int netconf_callback_ssh_hostkey_check (const char* hostname, int keytype, const char* fingerprint)
{
	/* always approve */
	return (EXIT_SUCCESS);
}

char* netconf_callback_sshauth_password (const char* username, const char* hostname)
{
	char* buf;

	buf = malloc ((strlen(password) + 1) * sizeof(char));
	apr_cpystrn(buf, password, strlen(password) + 1);

	return (buf);
}

void netconf_callback_sshauth_interactive (const char* name,
		int name_len,
		const char* instruction,
		int instruction_len,
		int num_prompts,
		const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts,
		LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
		void** abstract)
{
	int i;

	for (i=0; i<num_prompts; i++) {
		responses[i].text = malloc ((strlen(password) + 1) * sizeof(char));
		apr_cpystrn(responses[i].text, password, strlen(password) + 1);
		responses[i].length = strlen(responses[i].text) + 1;
	}

	return;
}

static json_object *err_reply = NULL;
void netconf_callback_error_process(const char* tag,
		const char* type,
		const char* severity,
		const char* apptag,
		const char* path,
		const char* message,
		const char* attribute,
		const char* element,
		const char* ns,
		const char* sid)
{
	err_reply = json_object_new_object();
	json_object_object_add(err_reply, "type", json_object_new_int(REPLY_ERROR));
	if (tag) json_object_object_add(err_reply, "error-tag", json_object_new_string(tag));
	if (type) json_object_object_add(err_reply, "error-type", json_object_new_string(type));
	if (severity) json_object_object_add(err_reply, "error-severity", json_object_new_string(severity));
	if (apptag) json_object_object_add(err_reply, "error-app-tag", json_object_new_string(apptag));
	if (path) json_object_object_add(err_reply, "error-path", json_object_new_string(path));
	if (message) json_object_object_add(err_reply, "error-message", json_object_new_string(message));
	if (attribute) json_object_object_add(err_reply, "bad-attribute", json_object_new_string(attribute));
	if (element) json_object_object_add(err_reply, "bad-element", json_object_new_string(element));
	if (ns) json_object_object_add(err_reply, "bad-namespace", json_object_new_string(ns));
	if (sid) json_object_object_add(err_reply, "session-id", json_object_new_string(sid));
}

static char* netconf_connect(server_rec* server, apr_pool_t* pool, apr_hash_t* conns, const char* host, const char* port, const char* user, const char* pass)
{
	struct nc_session* session;
	char *sid;
	char *session_key;

	/* connect to the requested NETCONF server */
	password = (char*)pass;
	session = nc_session_connect(host, (unsigned short) atoi (port), user, NULL);

	/* if connected successful, add session to the list */
	if (session != NULL) {
		/* generate hash for the session */
		sid = nc_session_get_id(session);
		session_key = gen_ncsession_hash(
				(host==NULL) ? "localhost" : host,
				(port==NULL) ? "830" : port,
				sid);
		free(sid);
		apr_hash_set(conns, apr_pstrdup(pool, session_key), APR_HASH_KEY_STRING, (void *) session);
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "NETCONF session established");
		return (session_key);
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Connection could not be established");
		return (NULL);
	}

}

static int netconf_close(server_rec* server, apr_hash_t* conns, char* session_key)
{
	struct nc_session *ns = NULL;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Key in hash to get: %s", session_key);
	ns = (struct nc_session *)apr_hash_get(conns, session_key, APR_HASH_KEY_STRING);
	if (ns != NULL) {
		nc_session_close (ns, "NETCONF session closed by client");
		nc_session_free (ns);
		ns = NULL;

		/* remove session from the active sessions list */
		apr_hash_set(conns, session_key, APR_HASH_KEY_STRING, NULL);
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "NETCONF session closed");

		return (EXIT_SUCCESS);
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Unknown session to close");
		return (EXIT_FAILURE);
	}
}

static int netconf_op(server_rec* server, apr_hash_t* conns, char* session_key, nc_rpc* rpc)
{
	struct nc_session *session = NULL;
	nc_reply* reply;
	int retval = EXIT_SUCCESS;

	/* check requests */
	if (rpc == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: rpc is not created");
		return (EXIT_FAILURE);
	}

	/* get session where send the RPC */
	session = (struct nc_session *)apr_hash_get(conns, session_key, APR_HASH_KEY_STRING);
	if (session != NULL) {
		/* send the request and get the reply */
		nc_session_send_rpc (session, rpc);
		if (nc_session_recv_reply (session, &reply) == 0) {
			if (nc_session_get_status(session) != NC_SESSION_STATUS_WORKING) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: receiving rpc-reply failed");
				netconf_close(server, conns, session_key);
				return (EXIT_FAILURE);
			}

			/* there is error handled by callback */
			return (EXIT_FAILURE);
		}

		switch (nc_reply_get_type (reply)) {
		case NC_REPLY_OK:
			retval = EXIT_SUCCESS;
			break;
		default:
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: unexpected rpc-reply");
			retval = EXIT_FAILURE;
			break;
		}
		nc_reply_free(reply);
		return (retval);
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Unknown session to process.");
		return (EXIT_FAILURE);
	}
}
static char* netconf_opdata(server_rec* server, apr_hash_t* conns, char* session_key, nc_rpc* rpc)
{
	struct nc_session *session = NULL;
	nc_reply* reply;
	char* data;

	/* check requests */
	if (rpc == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: rpc is not created");
		return (NULL);
	}

	/* get session where send the RPC */
	session = (struct nc_session *)apr_hash_get(conns, session_key, APR_HASH_KEY_STRING);
	if (session != NULL) {
		/* send the request and get the reply */
		nc_session_send_rpc (session, rpc);
		if (nc_session_recv_reply (session, &reply) == 0) {
			nc_rpc_free (rpc);
			if (nc_session_get_status(session) != NC_SESSION_STATUS_WORKING) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: receiving rpc-reply failed");
				netconf_close(server, conns, session_key);
				return (NULL);
			}

			/* there is error handled by callback */
			return (NULL);
		}
		nc_rpc_free (rpc);

		switch (nc_reply_get_type (reply)) {
		case NC_REPLY_DATA:
			if ((data = nc_reply_get_data (reply)) == NULL) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: no data from reply");
				return (NULL);
			}
			break;
		default:
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: unexpected rpc-reply");
			return (NULL);
		}
		nc_reply_free(reply);

		return (data);
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Unknown session to process.");
		return (NULL);
	}
}

static char* netconf_getconfig(server_rec* server, apr_hash_t* conns, char* session_key, NC_DATASTORE source, const char* filter)
{
	nc_rpc* rpc;
	struct nc_filter *f = NULL;
	char* data = NULL;

	/* create filter if set */
	if (filter != NULL) {
		f = nc_filter_new(NC_FILTER_SUBTREE, filter);
	}

	/* create requests */
	rpc = nc_rpc_getconfig (source, f);
	nc_filter_free(f);
	if (rpc == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: creating rpc request failed");
		return (NULL);
	}

	data = netconf_opdata(server, conns, session_key, rpc);
	nc_rpc_free (rpc);
	return (data);
}

static char* netconf_get(server_rec* server, apr_hash_t* conns, char* session_key, const char* filter)
{
	nc_rpc* rpc;
	struct nc_filter *f = NULL;
	char* data = NULL;

	/* create filter if set */
	if (filter != NULL) {
		f = nc_filter_new(NC_FILTER_SUBTREE, filter);
	}

	/* create requests */
	rpc = nc_rpc_get (f);
	nc_filter_free(f);
	if (rpc == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: creating rpc request failed");
		return (NULL);
	}

	data = netconf_opdata(server, conns, session_key, rpc);
	nc_rpc_free (rpc);
	return (data);
}

static int netconf_copyconfig(server_rec* server, apr_hash_t* conns, char* session_key, NC_DATASTORE source, NC_DATASTORE target, const char* config)
{
	nc_rpc* rpc;
	int retval = EXIT_SUCCESS;

	/* create requests */
	rpc = nc_rpc_copyconfig(source, target, config);
	if (rpc == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: creating rpc request failed");
		return (EXIT_FAILURE);
	}

	retval = netconf_op(server, conns, session_key, rpc);
	nc_rpc_free (rpc);
	return (retval);
}

static int netconf_editconfig(server_rec* server, apr_hash_t* conns, char* session_key, NC_DATASTORE target, NC_EDIT_DEFOP_TYPE defop, NC_EDIT_ERROPT_TYPE erropt, const char* config)
{
	nc_rpc* rpc;
	int retval = EXIT_SUCCESS;

	/* create requests */
	rpc = nc_rpc_editconfig(target, defop, erropt, config);
	if (rpc == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: creating rpc request failed");
		return (EXIT_FAILURE);
	}

	retval = netconf_op(server, conns, session_key, rpc);
	nc_rpc_free (rpc);
	return (retval);
}

server_rec* clb_print_server;
int clb_print(const char* msg)
{
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, clb_print_server, msg);
	return (0);
}

/*
 * This is actually implementation of NETCONF client
 * - requests are received from UNIX socket in the predefined format
 * - results are replied through the same way
 * - the daemon run as a separate process, but it is started and stopped
 *   automatically by Apache.
 *
 */
static void forked_proc(apr_pool_t * pool, server_rec * server)
{
	struct sockaddr_un local, remote;
	int lsock, client;
	socklen_t len, len2;
	struct pollfd fds;
	int status;
	mod_netconf_cfg *cfg;
	json_object *request, *reply;
	int operation;
	char* session_key, *data;
	const char *msgtext;
	const char *host, *port, *user, *pass;
	const char *target, *source, *filter, *config, *defop, *erropt;
	NC_DATASTORE ds_type1, ds_type2;
	NC_EDIT_DEFOP_TYPE defop_type = 0;
	NC_EDIT_ERROPT_TYPE erropt_type = 0;

	apr_hash_t *netconf_sessions_list;
	char buffer[BUFFER_SIZE];

	/* change uid and gid of process for security reasons */
	unixd_setup_child();

	cfg = ap_get_module_config(server->module_config, &netconf_module);
	if (cfg == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Getting mod_netconf configuration failed");
		return;
	}

	/* create listening UNIX socket to accept incoming connections */
	if ((lsock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Creating socket failed (%s)", strerror(errno));
		return;
	}

	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, cfg->sockname, sizeof(local.sun_path));
	unlink(local.sun_path);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(local.sun_path);

	if (bind(lsock, (struct sockaddr *) &local, len) == -1) {
		if (errno == EADDRINUSE) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "mod_netconf socket address already in use");
			close(lsock);
			exit(0);
		}
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Binding socket failed (%s)", strerror(errno));
		close(lsock);
		return;
	}

	if (listen(lsock, MAX_SOCKET_CL) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Setting up listen socket failed (%s)", strerror(errno));
		close(lsock);
		return;
	}

	/* prepare internal lists */
	netconf_sessions_list = apr_hash_make(pool);

	/* setup libnetconf's callbacks */
	nc_verbosity(NC_VERB_DEBUG);
	clb_print_server = server;
	nc_callback_print(clb_print);
	nc_callback_ssh_host_authenticity_check(netconf_callback_ssh_hostkey_check);
	nc_callback_sshauth_interactive(netconf_callback_sshauth_interactive);
	nc_callback_sshauth_password(netconf_callback_sshauth_password);
	nc_callback_error_reply(netconf_callback_error_process);

	/* disable publickey authentication */
	nc_ssh_pref(NC_SSH_AUTH_PUBLIC_KEYS, -1);

	while (isterminated == 0) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "waiting for another client's request");

		/* open incoming connection if any */
		len2 = sizeof(remote);
		client = accept(lsock, (struct sockaddr *) &remote, &len2);
		if (client == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			apr_sleep(SLEEP_TIME);
			continue;
		} else if (client == -1 && (errno == EINTR)) {
			continue;
		} else if (client == -1) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Accepting mod_netconf client connection failed (%s)", strerror(errno));
			continue;
		}
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "client's socket accepted.");

		/* set client's socket as non-blocking */
		//fcntl(client, F_SETFL, fcntl(client, F_GETFL, 0) | O_NONBLOCK);

		while (1) {
			fds.fd = client;
			fds.events = POLLIN;
			fds.revents = 0;

			status = poll(&fds, 1, 1000);

			if (status == 0 || (status == -1 && (errno == EAGAIN || (errno == EINTR && isterminated == 0)))) {
				/* poll was interrupted - check if the isterminated is set and if not, try poll again */
				//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "poll interrupted");
				continue;
			} else if (status < 0) {
				/* 0:  poll time outed
				 *     close socket and ignore this request from the client, it can try it again
				 * -1: poll failed
				 *     something wrong happend, close this socket and wait for another request
				 */
				//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "poll failed, status %d(%d: %s)", status, errno, strerror(errno));
				close(client);
				break;
			}
			/* status > 0 */

			/* check the status of the socket */

			/* if nothing to read and POLLHUP (EOF) or POLLERR set */
			if ((fds.revents & POLLHUP) || (fds.revents & POLLERR)) {
				/* close client's socket (it's probably already closed by client */
				//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "socket error (%d)", fds.revents);
				close(client);
				break;
			}

			if ((len2 = recv(client, buffer, BUFFER_SIZE, 0)) <= 0) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "receiving failed %d (%s)", errno, strerror(errno));
				continue;
			} else {
				request = json_tokener_parse(buffer);
				operation = json_object_get_int(json_object_object_get(request, "type"));

				session_key = (char*) json_object_get_string(json_object_object_get(request, "session"));
				/* DO NOT FREE session_key HERE, IT IS PART OF REQUEST */
				if (operation != MSG_CONNECT && session_key == NULL) {
					reply =  json_object_new_object();
					json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
					json_object_object_add(reply, "error-message", json_object_new_string("Missing session specification."));
					msgtext = json_object_to_json_string(reply);
					send(client, msgtext, strlen(msgtext) + 1, 0);
					json_object_put(reply);
					/* there is some stupid client, so close the connection to give a chance to some other client */
					close(client);
					break;
				}

				/* null global JSON error-reply */
				err_reply = NULL;

				/* process required operation */
				switch (operation) {
				case MSG_CONNECT:
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Request: Connect");

					host = json_object_get_string(json_object_object_get(request, "host"));
					port = json_object_get_string(json_object_object_get(request, "port"));
					user = json_object_get_string(json_object_object_get(request, "user"));
					pass = json_object_get_string(json_object_object_get(request, "pass"));
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "host: %s, port: %s, user: %s", host, port, user);
					session_key = netconf_connect(server, pool, netconf_sessions_list, host, port, user, pass);
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "hash: %s", session_key);

					reply =  json_object_new_object();
					if (session_key == NULL) {
						/* negative reply */
						if (err_reply == NULL) {
							json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
							json_object_object_add(reply, "error-message", json_object_new_string("Connecting NETCONF server failed."));
						} else {
							/* use filled err_reply from libnetconf's callback */
							json_object_put(reply);
							reply = err_reply;
						}
					} else {
						/* positive reply */
						json_object_object_add(reply, "type", json_object_new_int(REPLY_OK));
						json_object_object_add(reply, "session", json_object_new_string(session_key));

						free(session_key);
					}

					break;
				case MSG_GET:
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Request: get-config (session %s)", session_key);

					filter = json_object_get_string(json_object_object_get(request, "filter"));

					reply =  json_object_new_object();

					if ((data = netconf_get(server, netconf_sessions_list, session_key, filter)) == NULL) {
						if (err_reply == NULL) {
							json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
							json_object_object_add(reply, "error-message", json_object_new_string("get failed."));
						} else {
							/* use filled err_reply from libnetconf's callback */
							json_object_put(reply);
							reply = err_reply;
						}
					} else {
						json_object_object_add(reply, "type", json_object_new_int(REPLY_DATA));
						json_object_object_add(reply, "data", json_object_new_string(data));
					}
					break;
				case MSG_GETCONFIG:
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Request: get-config (session %s)", session_key);

					source = json_object_get_string(json_object_object_get(request, "source"));
					filter = json_object_get_string(json_object_object_get(request, "filter"));

					reply = json_object_new_object();

					/* if source is NULL, set valid string for strcmp, that is invalid for the following test */
					source = (source == NULL) ? "": source;
					if (strcmp(source, "running") == 0) {
						ds_type1 = NC_DATASTORE_RUNNING;
					} else if (strcmp(source, "startup") == 0) {
						ds_type1 = NC_DATASTORE_STARTUP;
					} else if (strcmp(source, "candidate") == 0) {
						ds_type1 = NC_DATASTORE_CANDIDATE;
					} else {
						json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
						json_object_object_add(reply, "error-message", json_object_new_string("Invalid source repository type requested."));
						break;
					}

					if ((data = netconf_getconfig(server, netconf_sessions_list, session_key, ds_type1, filter)) == NULL) {
						if (err_reply == NULL) {
							json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
							json_object_object_add(reply, "error-message", json_object_new_string("get-config failed."));
						} else {
							/* use filled err_reply from libnetconf's callback */
							json_object_put(reply);
							reply = err_reply;
						}
					} else {
						json_object_object_add(reply, "type", json_object_new_int(REPLY_DATA));
						json_object_object_add(reply, "data", json_object_new_string(data));
					}
					break;
				case MSG_EDITCONFIG:
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Request: edit-config (session %s)", session_key);

					reply = json_object_new_object();

					defop = json_object_get_string(json_object_object_get(request, "default-operation"));
					if (defop != NULL) {
						if (strcmp(defop, "merge") == 0) {
							defop_type = NC_EDIT_DEFOP_MERGE;
						} else if (strcmp(defop, "replace") == 0) {
							defop_type = NC_EDIT_DEFOP_REPLACE;
						} else if (strcmp(defop, "none") == 0) {
							defop_type = NC_EDIT_DEFOP_NONE;
						} else {
							json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
							json_object_object_add(reply, "error-message", json_object_new_string("Invalid default-operation parameter."));
							break;
						}
					} else {
						defop_type = 0;
					}

					erropt = json_object_get_string(json_object_object_get(request, "error-option"));
					if (erropt != NULL) {
						if (strcmp(erropt, "continue-on-error") == 0) {
							erropt_type = NC_EDIT_ERROPT_CONT;
						} else if (strcmp(erropt, "stop-on-error") == 0) {
							erropt_type = NC_EDIT_ERROPT_STOP;
						} else if (strcmp(erropt, "rollback-on-error") == 0) {
							erropt_type = NC_EDIT_ERROPT_ROLLBACK;
						} else {
							json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
							json_object_object_add(reply, "error-message", json_object_new_string("Invalid error-option parameter."));
							break;
						}
					} else {
						erropt_type = 0;
					}

					/* if target is NULL, set valid string for strcmp, that is invalid for the following test */
					target = json_object_get_string(json_object_object_get(request, "target"));
					target = (target == NULL) ? "": target;
					if (strcmp(target, "running") == 0) {
						ds_type1 = NC_DATASTORE_RUNNING;
					} else if (strcmp(target, "startup") == 0) {
						ds_type1 = NC_DATASTORE_STARTUP;
					} else if (strcmp(target, "candidate") == 0) {
						ds_type1 = NC_DATASTORE_CANDIDATE;
					} else {
						json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
						json_object_object_add(reply, "error-message", json_object_new_string("Invalid target repository type requested."));
						break;
					}

					config = json_object_get_string(json_object_object_get(request, "config"));
					if (config == NULL) {
						json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
						json_object_object_add(reply, "error-message", json_object_new_string("Invalid config data parameter."));
						break;
					}

					if (netconf_editconfig(server, netconf_sessions_list, session_key, ds_type1, defop_type, erropt_type, config) != EXIT_SUCCESS) {
						if (err_reply == NULL) {
							json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
							json_object_object_add(reply, "error-message", json_object_new_string("edit-config failed."));
						} else {
							/* use filled err_reply from libnetconf's callback */
							json_object_put(reply);
							reply = err_reply;
						}
					} else {
						json_object_object_add(reply, "type", json_object_new_int(REPLY_OK));
					}
					break;
				case MSG_COPYCONFIG:
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Request: copy-config (session %s)", session_key);
					source = target = config = NULL;

					source = json_object_get_string(json_object_object_get(request, "source"));
					target = json_object_get_string(json_object_object_get(request, "target"));

					reply = json_object_new_object();

					if (source != NULL) {
						if (strcmp(source, "running") == 0) {
							ds_type1 = NC_DATASTORE_RUNNING;
						} else if (strcmp(source, "startup") == 0) {
							ds_type1 = NC_DATASTORE_STARTUP;
						} else if (strcmp(source, "candidate") == 0) {
							ds_type1 = NC_DATASTORE_CANDIDATE;
						} else {
							json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
							json_object_object_add(reply, "error-message", json_object_new_string("Invalid source repository type requested."));
							break;
						}
					} else {
						ds_type1 = NC_DATASTORE_NONE;
						config = json_object_get_string(json_object_object_get(request, "config"));
					}

					/* if target is NULL, set valid string for strcmp, that is invalid for the following test */
					target = (target == NULL) ? "": target;
					if (strcmp(target, "running") == 0) {
						ds_type2 = NC_DATASTORE_RUNNING;
					} else if (strcmp(target, "startup") == 0) {
						ds_type2 = NC_DATASTORE_STARTUP;
					} else if (strcmp(target, "candidate") == 0) {
						ds_type2 = NC_DATASTORE_CANDIDATE;
					} else {
						json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
						json_object_object_add(reply, "error-message", json_object_new_string("Invalid target repository type requested."));
						break;
					}

					if (target == NULL || (source == NULL && config == NULL)) {
						json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
						json_object_object_add(reply, "error-message", json_object_new_string("invalid input parameters."));
					} else {
						if (netconf_copyconfig(server, netconf_sessions_list, session_key, ds_type1, ds_type2, config) != EXIT_SUCCESS) {
							if (err_reply == NULL) {
								json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
								json_object_object_add(reply, "error-message", json_object_new_string("copy-config failed."));
							} else {
								/* use filled err_reply from libnetconf's callback */
								json_object_put(reply);
								reply = err_reply;
							}
						} else {
							json_object_object_add(reply, "type", json_object_new_int(REPLY_OK));
						}
					}
					break;
				case MSG_DISCONNECT:
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Request: Disconnect session %s", session_key);

					reply =  json_object_new_object();
					if (netconf_close(server, netconf_sessions_list, session_key) != EXIT_SUCCESS) {
						if (err_reply == NULL) {
							json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
							json_object_object_add(reply, "error-message", json_object_new_string("Invalid session identifier."));
						} else {
							/* use filled err_reply from libnetconf's callback */
							json_object_put(reply);
							reply = err_reply;
						}
					} else {
						json_object_object_add(reply, "type", json_object_new_int(REPLY_OK));
					}
					break;
				default:
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Unknown mod_netconf operation requested (%d)", operation);
					reply =  json_object_new_object();
					json_object_object_add(reply, "type", json_object_new_int(REPLY_ERROR));
					json_object_object_add(reply, "error-message", json_object_new_string("Operation not supported."));
					break;
				}
				json_object_put(request);

				/* send reply to caller */
				if (reply != NULL) {
					msgtext = json_object_to_json_string(reply);
					send(client, msgtext, strlen(msgtext) + 1, 0);
					json_object_put(reply);
				} else {
					break;
				}
			}
		}
	}

	close(lsock);

	ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Exiting from the mod_netconf daemon");

	exit(APR_SUCCESS);
}

static void *mod_netconf_create_conf(apr_pool_t * pool, server_rec * s)
{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "Init netconf module config");

	mod_netconf_cfg *config = apr_pcalloc(pool, sizeof(mod_netconf_cfg));
	apr_pool_create(&config->pool, pool);
	config->forkproc = NULL;
	config->sockname = SOCKET_FILENAME;

	return (void *)config;
}

static int mod_netconf_master_init(apr_pool_t * pconf, apr_pool_t * ptemp,
		  apr_pool_t * plog, server_rec * s)
{
	mod_netconf_cfg *config;
	apr_status_t res;

	/* These two help ensure that we only init once. */
	void *data;
	const char *userdata_key = "netconf_ipc_init";

	/*
	 * The following checks if this routine has been called before.
	 * This is necessary because the parent process gets initialized
	 * a couple of times as the server starts up.
	 */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (!data) {
		apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
		return (OK);
	}

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "creating mod_netconf daemon");
	config = ap_get_module_config(s->module_config, &netconf_module);

	if (config && config->forkproc == NULL) {
		config->forkproc = apr_pcalloc(config->pool, sizeof(apr_proc_t));
		res = apr_proc_fork(config->forkproc, config->pool);
		switch (res) {
		case APR_INCHILD:
			/* set signal handler */
			apr_signal_init(config->pool);
			apr_signal(SIGTERM, signal_handler);

			/* log start of the separated NETCONF communication process */
			ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "mod_netconf daemon started (PID %d)", getpid());

			/* start main loop providing NETCONF communication */
			forked_proc(config->pool, s);

			/* I never should be here, wtf?!? */
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_netconf daemon unexpectedly stopped");
			exit(APR_EGENERAL);
			break;
		case APR_INPARENT:
			/* register child to be killed (SIGTERM) when the module config's pool dies */
			apr_pool_note_subprocess(config->pool, config->forkproc, APR_KILL_AFTER_TIMEOUT);
			break;
		default:
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_proc_fork() failed");
			break;
		}
	} else {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "mod_netconf misses configuration structure");
	}

	return OK;
}

/**
 * Register module hooks
 */
static void mod_netconf_register_hooks(apr_pool_t * p)
{
	ap_hook_post_config(mod_netconf_master_init, NULL, NULL, APR_HOOK_LAST);
}

static const char* cfg_set_socket_path(cmd_parms* cmd, void* cfg, const char* arg)
{
	((mod_netconf_cfg*)cfg)->sockname = apr_pstrdup(cmd->pool, arg);
	return NULL;
}

static const command_rec netconf_cmds[] = {
		AP_INIT_TAKE1("NetconfSocket", cfg_set_socket_path, NULL, OR_ALL, "UNIX socket path for mod_netconf communication."),
		{NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA netconf_module = {
	STANDARD20_MODULE_STUFF,
	NULL,			/* create per-dir    config structures */
	NULL,			/* merge  per-dir    config structures */
	mod_netconf_create_conf,	/* create per-server config structures */
	NULL,			/* merge  per-server config structures */
	netconf_cmds,			/* table of config file commands       */
	mod_netconf_register_hooks	/* register hooks                      */
};
