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

#include <libnetconf.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

#define MAX_PROCS 5
#define SOCKET_FILENAME "/tmp/pcon.sock"
#define MAX_SOCKET_CL 10
#define BUFFER_SIZE 4096

/* sleep in master process for non-blocking socket reading */
#define SLEEP_TIME 200

#ifndef offsetof
#define offsetof(type, member) ((size_t) ((type *) 0)->member)
#endif

struct timeval timeout = { 1, 0 };

#define MSG_OK 0
#define MSG_OPEN  1
#define MSG_DATA  2
#define MSG_CLOSE 3
#define MSG_ERROR 4
#define MSG_UNKNOWN 5

typedef struct sck_message {
	uint8_t type;
	char session_key[APR_SHA1_DIGESTSIZE + 1];
} __attribute__ ((packed)) sck_message_t;

module AP_MODULE_DECLARE_DATA netconf_module;

typedef struct {
	apr_proc_t *forkproc;
	apr_pool_t *pool;
	uint32_t count;
} mod_netconf_srv_cfg;

volatile int isterminated = 0;

static char* password;


static void signal_handler(int sign)
{
	switch (sign) {
	case SIGTERM:
		isterminated = 1;
		fprintf(stderr, "got TERM signal... %s\n",
			apr_signal_description_get(sign));
		break;
	default:
		printf("%s\n", apr_signal_description_get(sign));
		break;
	}
}

static int gen_ncsession_hash(char *s, const int len, const char* hostname, const char* port, const char* sid)
{
	if (s == NULL || len != (APR_SHA1_DIGESTSIZE + 1)) {
		return (APR_EINVAL);
	}
	apr_sha1_ctx_t sha1_ctx;
	apr_sha1_init(&sha1_ctx);
	apr_sha1_update(&sha1_ctx, hostname, strlen(hostname));
	apr_sha1_update(&sha1_ctx, port, strlen(port));
	apr_sha1_update(&sha1_ctx, sid, strlen(sid));
	apr_sha1_final((unsigned char*)s, &sha1_ctx);

	/* add missing terminating null byte */
	s[APR_SHA1_DIGESTSIZE] = 0;

	return (APR_SUCCESS);
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

static void handle_msg_open(server_rec* server, int client, apr_hash_t* conns, char** address)
{
	sck_message_t message;
	struct nc_session* session;
	char *hostname, *port, *username, *sid;

	hostname = address[0];
	port = address[1];
	username = address[2];

	/* connect to the requested NETCONF server */
	password = address[3];
	session = nc_session_connect(hostname, (unsigned short) atoi (port), username, NULL);
	password = NULL;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "host: %s, port: %s, user: %s", hostname, port, username);

	/* clear plaintext password */
	size_t size = strlen(address[3]);
	memset(address[3], 0, size + 1);

	/* if connected successful, add session to the list */
	if (session != NULL) {
		/* generate hash for the session */
		sid = nc_session_get_id(session);
		gen_ncsession_hash(message.session_key, APR_SHA1_DIGESTSIZE + 1, hostname, port, sid);
		free(sid);

		apr_hash_set(conns, message.session_key, APR_HASH_KEY_STRING, (void *) session);
		send(client, &message, sizeof(message), 0);
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "NETCONF session established");
		return;
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Connection could not be established");
	}

	message.type = MSG_ERROR;
	memset(&message.session_key, 0, sizeof(message.session_key));
	send(client, &message, sizeof(message), 0);
}

static void handle_msg_close(server_rec* server, int client, apr_hash_t* conns, char* session_key)
{
	struct nc_session *ns = NULL;
	sck_message_t reply;

	ns = (struct nc_session *)apr_hash_get(conns, session_key, APR_HASH_KEY_STRING);
	if (ns != NULL) {
		nc_session_close (ns, "NETCONF session closed by client");
		nc_session_free (ns);
		ns = NULL;

		/* remove session from the active sessions list */
		apr_hash_set(conns, session_key, APR_HASH_KEY_STRING, NULL);
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "NETCONF session closed");
		reply.type = MSG_OK;
		memset(&reply.session_key, 0, sizeof(reply.session_key));
		send(client, &reply, sizeof(reply), 0);
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Unknown session to close");
		reply.type = MSG_ERROR;
		memset(&reply.session_key, 0, sizeof(reply.session_key));
		send(client, &reply, sizeof(reply), 0);
	}
}

static void handle_netconf_request(server_rec* server, int client, apr_hash_t* conns, char* session_key)
{
	struct nc_session *session = NULL;
	sck_message_t client_reply;
	NC_DATASTORE target = NC_DATASTORE_RUNNING;
	nc_rpc* rpc;
	nc_reply* reply;
	char* data, *client_reply_data;

	session = (struct nc_session *)apr_hash_get(conns, session_key, APR_HASH_KEY_STRING);
	if (session != NULL) {
		/* create requests */
		rpc = nc_rpc_getconfig (target, NULL);
		if (rpc == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: creating rpc request failed");
			goto error_reply;
		}
		/* send the request and get the reply */
		nc_session_send_rpc (session, rpc);
		if (nc_session_recv_reply (session, &reply) == 0) {
			nc_rpc_free (rpc);
			if (nc_session_get_status(session) != NC_SESSION_STATUS_WORKING) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: receiving rpc-reply failed");
				handle_msg_close(server, client, conns, session_key);
				goto error_reply;
			}
			/* there is error handled by callback */
			return;
		}
		nc_rpc_free (rpc);

		switch (nc_reply_get_type (reply)) {
		case NC_REPLY_DATA:
		case NC_REPLY_ERROR:
			data = nc_reply_dump(reply);
			break;
		default:
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: unexpected rpc-reply");
			goto error_reply;
		}
		nc_reply_free(reply);

		if (!data) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: no data from reply");
			goto error_reply;
		}

		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "NETCONF get-config is done");
		client_reply_data = malloc(sizeof(char) * (1 + strlen(data) + 1)); /* 1B message type, message length, 1B terminating null */
		if (client_reply_data == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "mod_netconf: allocating memory for client reply failed");
			goto error_reply;
		}
		client_reply_data[0] = MSG_DATA;
		apr_cpystrn(&client_reply_data[1], data, strlen(data) + 1);
		send(client, client_reply_data, strlen(client_reply_data) + 1, 0);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "sending message from daemon: %x", client_reply_data[0]);
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Unknown session to close");
		goto error_reply;
	}

	return;

error_reply:
	client_reply.type = MSG_ERROR;
	memset(&client_reply.session_key, 0, sizeof(client_reply.session_key));
	send(client, &client_reply, sizeof(client_reply), 0);
}

static void get_target_address(char *address[4], char *cred)
{
	int i;

	/* <MSG_TYPE> <host> \0 <port> \0 <user> \0 <pass> \0 */

	/* hostname */
	address[0] = &cred[0];

	/* process the rest in loop */
	for (i = 1; i < 4; i++) {
		/* port, user, password */
		address[i] = address[i-1] + strlen(address[i-1]) + 1;
	}
}

server_rec* clb_print_server;
int clb_print(const char* msg)
{
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, clb_print_server, msg);
	return (0);
}

static void forked_proc(apr_pool_t * pool, server_rec * server)
{
	struct sockaddr_un local, remote;
	int lsock, client;
	socklen_t len, len2;
	struct pollfd fds;
	int status;

	apr_hash_t *netconf_sessions_list;
	char buffer[BUFFER_SIZE];
	char *address[4];

	/* change uid and gid of proccess for security reasons */
	unixd_setup_child();

	/* create listening UNIX socket to accept incomming connections */

	if ((lsock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Creating socket failed (%s)", strerror(errno));
		return;
	}

	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, SOCKET_FILENAME, sizeof(local.sun_path));
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
		fcntl(client, F_SETFL, fcntl(client, F_GETFL, 0) | O_NONBLOCK);

		while (1) {
			fds.fd = client;
			fds.events = POLLIN;
			fds.revents = 0;

			status = poll(&fds, 1, 100);

			if (status == -1 && errno == EINTR && isterminated == 0) {
				/* poll was interrupted - check if the isterminated is set and if not, try poll again */
				continue;
			} else if (status <= 0) {
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

			if ((len2 = recv(client, buffer, BUFFER_SIZE, 0)) <= 0) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "receiving failed %d (%s)", errno, strerror(errno));
				continue;
			} else {
				/* got message from client */
				buffer[len2] = 0;
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "received from client: %s", buffer);

				/* message type */
				switch (buffer[0]) {
				case MSG_OPEN:
					get_target_address(address, &buffer[1]);
					handle_msg_open(server, client, netconf_sessions_list, address);
					break;
				case MSG_DATA:
					/* netconf data */
					handle_netconf_request(server, client, netconf_sessions_list, &buffer[1]);
					break;
				case MSG_CLOSE:
					handle_msg_close(server, client, netconf_sessions_list, &buffer[1]);
					break;
				default:
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Unknown mod_netconf message type");
					sck_message_t message;
					message.type = MSG_UNKNOWN;
					memset(&message.session_key, 0, sizeof(message.session_key));
					send(client, (void *) &message, sizeof(message), 0);
					break;
				}
			}
		}
	}

	close(lsock);

	ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "Exiting from the mod_netconf daemon");

	exit(APR_SUCCESS);
}

static void *mod_netconf_create_srv_conf(apr_pool_t * pool, server_rec * s)
{
	mod_netconf_srv_cfg *srv = apr_pcalloc(pool, sizeof(mod_netconf_srv_cfg));
	apr_pool_create(&srv->pool, pool);
	srv->forkproc = NULL;
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "init netconf module config");
	if (srv == NULL) {
		srv = apr_pcalloc(pool, sizeof(mod_netconf_srv_cfg));
		apr_pool_create(&srv->pool, pool);
	}
	return (void *)srv;
}

static int mod_netconf_master_init(apr_pool_t * pconf, apr_pool_t * ptemp,
		  apr_pool_t * plog, server_rec * s)
{
	/* These two help ensure that we only init once. */
	void *data;
	const char *userdata_key = "netconf_ipc_init_module";

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

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "creating mod_netconf master process");
	mod_netconf_srv_cfg *srv = ap_get_module_config(s->module_config, &netconf_module);

	if (srv->forkproc == NULL) {
		srv->forkproc = apr_pcalloc(srv->pool, sizeof(apr_proc_t));
		apr_status_t res = apr_proc_fork(srv->forkproc, srv->pool);
		switch (res) {
		case APR_INCHILD:
			/* set signal handler */
			apr_signal_init(srv->pool);
			apr_signal(SIGTERM, signal_handler);

			/* log start of the separated NETCONF communication process */
			ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "mod_netconf master process created (PID %d)", getpid());

			/* start main loop providing NETCONF communication */
			forked_proc(srv->pool, s);

			/* I never should be here */
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_netconf master process broke the main loop");
			exit(APR_EGENERAL);
			break;
		case APR_INPARENT:
			/* register child to be killed (SIGTERM) when the module config's pool dies */
			apr_pool_note_subprocess(srv->pool, srv->forkproc, APR_KILL_AFTER_TIMEOUT);
			break;
		default:
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_proc_fork() failed");
			break;
		}
	}

	return OK;
}

static int mod_netconf_fixups(request_rec *r)
{
	apr_pool_t *temp_pool = NULL;
	char* operation;
	char *cred;
	int len;
	int sock = -1;
	char buffer[BUFFER_SIZE];
	struct sockaddr_un addr;

	/* process only requests for the mod_netconf handler */
	if (!r->handler || (strcmp(r->handler, "netconf") != 0)) {
		return DECLINED;
	}

	/* allow running module only as subrequest */
	if (r->main == NULL) {
		return DECLINED;
	}

	/* create temporary pool */
	apr_pool_create(&temp_pool, NULL);

	operation = apr_pstrdup(temp_pool, apr_table_get(r->subprocess_env, "NETCONF_OP"));
	if (operation == NULL) {
		apr_pool_destroy(temp_pool);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* connect to the daemon */
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Cannot create client's mod_netconf socket");
		apr_pool_destroy(temp_pool);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_FILENAME, sizeof(addr.sun_path));
	len = strlen(addr.sun_path) + sizeof(addr.sun_family);
	if (connect(sock, (struct sockaddr *) &addr, len) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Cannot connect to the mod_netconf daemon");
		apr_pool_destroy(temp_pool);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* process the request */
	if (strcmp(operation, "connect") == 0) {
		char *host = apr_pstrdup(r->pool, apr_table_get(r->subprocess_env, "NETCONF_HOST"));
		char *port = apr_pstrdup(r->pool, apr_table_get(r->subprocess_env, "NETCONF_PORT"));
		char *user = apr_pstrdup(r->pool, apr_table_get(r->subprocess_env, "NETCONF_USER"));
		char *pass = apr_pstrdup(r->pool, apr_table_get(r->subprocess_env, "NETCONF_PASS"));

		/* <MSG_TYPE><host>\0<port>\0<user>\0<pass>\0 */
		cred = apr_psprintf(temp_pool, " %s %s %s %s", host, port, user, pass);
		cred[len = 0] = MSG_OPEN;
		cred[len += strlen(host) + 1] = 0; /* <host>\0 */
		cred[len += strlen(port) + 1] = 0; /* <port>\0 */
		cred[len += strlen(user) + 1] = 0; /* <user>\0 */
		/* <pass>\0 is already done from printf, but we need to count index for send */
		cred[len += strlen(pass) + 1] = 0;

		send(sock, cred, len, 0);
		len = recv(sock, buffer, BUFFER_SIZE, 0);

		if (len < sizeof(sck_message_t)) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Invalid reply from mod_netconf daemon");
			apr_pool_destroy(temp_pool);
			return HTTP_INTERNAL_SERVER_ERROR;
		} else if (buffer[0] != MSG_OK) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Cannot connect with NETCONF server");
			apr_pool_destroy(temp_pool);
			return HTTP_INTERNAL_SERVER_ERROR;
		} else {
			/* ok, received OK message */
			//apr_table_set(r->subprocess_env, "NETCONF_NSID", &(buffer[1]));
			apr_table_set(r->main->subprocess_env, "NETCONF_NSID", "somestring");
		}
	} else if (strcmp(operation, "disconnect") == 0) {

	} else if (strcmp(operation, "get-config") == 0) {

	} else {
		return HTTP_NOT_IMPLEMENTED;
	}

	if (sock != -1) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "client closes socket");
		close (sock);
	}
	if (temp_pool != NULL) {
		apr_pool_destroy(temp_pool);
	}

	return OK;
}

/**
 * Testing content handler
 * This function should handle NETCONF and return UI
 */
static int mod_netconf_handler(request_rec * r)
{
	/* pseudo code of args to apr_proc_create() */
	if (!r->handler || (strcmp(r->handler, "netconf") != 0)) {
		return DECLINED;
	}

	/* everything was done in fixups */
	return OK;
}

/**
 * Register module hooks
 */
static void mod_netconf_register_hooks(apr_pool_t * p)
{
	ap_hook_fixups(mod_netconf_fixups, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_handler(mod_netconf_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(mod_netconf_master_init, NULL, NULL, APR_HOOK_LAST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA netconf_module = {
	STANDARD20_MODULE_STUFF,
	NULL,			/* create per-dir    config structures */
	NULL,			/* merge  per-dir    config structures */
	mod_netconf_create_srv_conf,	/* create per-server config structures */
	NULL,			/* merge  per-server config structures */
	NULL,			/* table of config file commands       */
	mod_netconf_register_hooks	/* register hooks                      */
};
