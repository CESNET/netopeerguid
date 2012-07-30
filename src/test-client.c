/*!
 * \file test-client.c
 * \brief Testing client sending JSON requsts to the mod_netconf socket
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \date 2012
 */
/*
 * Copyright (C) 2012 CESNET
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <json/json.h>

#define SOCKET_FILENAME "/tmp/mod_netconf.sock"
#define BUFFER_SIZE 4096

typedef enum MSG_TYPE {
	REPLY_OK,
	REPLY_DATA,
	REPLY_ERROR,
	REPLY_INFO,
	MSG_CONNECT,
	MSG_DISCONNECT,
	MSG_GET,
	MSG_GETCONFIG,
	MSG_EDITCONFIG,
	MSG_COPYCONFIG,
	MSG_DELETECONFIG,
	MSG_LOCK,
	MSG_UNLOCK,
	MSG_KILL,
	MSG_INFO,
	MSG_GENERIC
} MSG_TYPE;

void print_help(char* progname)
{
	printf("Usage: %s <command>\n", progname);
	printf("Available commands:\n");
	printf("\tconnect\n");
	printf("\tdisconnect\n");
	printf("\tcopy-config\n");
	printf("\tdelete-config\n");
	printf("\tedit-config\n");
	printf("\tget\n");
	printf("\tget-config\n");
	printf("\tkill-session\n");
	printf("\tlock\n");
	printf("\tunlock\n");
	printf("\tinfo\n");
	printf("\tgeneric\n");
}

int main (int argc, char* argv[])
{
	json_object* msg = NULL, *reply = NULL;
	const char* msg_text;
	int sock;
	struct sockaddr_un addr;
	size_t len;
	char buffer[BUFFER_SIZE];
	char* line = NULL;
	int i, alen;

	if (argc != 2) {
		print_help(argv[0]);
		return (2);
	}

	/* connect to the daemon */
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "Creating socket failed (%s)", strerror(errno));
		return (EXIT_FAILURE);
	}
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_FILENAME, sizeof(addr.sun_path));
	len = strlen(addr.sun_path) + sizeof(addr.sun_family);
	if (connect(sock, (struct sockaddr *) &addr, len) == -1) {
		fprintf(stderr, "Connecting to mod_netconf (%s) failed (%s)", SOCKET_FILENAME, strerror(errno));
		close(sock);
		return (EXIT_FAILURE);
	}

	line = malloc(sizeof(char) * BUFFER_SIZE);

	if (strcmp(argv[1], "connect") == 0) {
		/*
		 * create NETCONF session
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_CONNECT));
		printf("Hostname: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "host", json_object_new_string(line));
		printf("Port: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "port", json_object_new_string(line));
		printf("Username: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "user", json_object_new_string(line));
		printf("Password: ");
		system("stty -echo");
		getline (&line, &len, stdin);
		system("stty echo");
		printf("\n");
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "pass", json_object_new_string(line));
	} else if (strcmp(argv[1], "disconnect") == 0) {
		/*
		 * Close NETCONF session
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_DISCONNECT));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
	} else if (strcmp(argv[1], "copy-config") == 0) {
		/*
		 * NETCONF <copy-config>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_COPYCONFIG));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
		printf("Source (running|startup|candidate): ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		if (strlen(line) > 0) {
			json_object_object_add(msg, "source", json_object_new_string(line));
		} else {
			printf("Configuration data: ");
			getline (&line, &len, stdin);
			line[(strlen(line)-1)] = 0;
			json_object_object_add(msg, "config", json_object_new_string(line));
		}
		printf("Target (running|startup|candidate): ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "target", json_object_new_string(line));
	} else if (strcmp(argv[1], "delete-config") == 0) {
		/*
		 * NETCONF <delete-config>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_DELETECONFIG));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
		printf("Target (running|startup|candidate): ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "target", json_object_new_string(line));
	} else if (strcmp(argv[1], "edit-config") == 0) {
		/*
		 * NETCONF <edit-config>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_EDITCONFIG));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
		printf("Target (running|startup|candidate): ");
		getline(&line, &len, stdin);
		line[(strlen(line) - 1)] = 0;
		json_object_object_add(msg, "target", json_object_new_string(line));
		printf("Default operation (merge|replace|none): ");
		getline(&line, &len, stdin);
		line[(strlen(line) - 1)] = 0;
		if (strlen(line) > 0) {
			json_object_object_add(msg, "default-operation", json_object_new_string(line));
		}
		printf("Error option (stop-on-error|continue-on-error|rollback-on-error): ");
		getline(&line, &len, stdin);
		line[(strlen(line) - 1)] = 0;
		if (strlen(line) > 0) {
			json_object_object_add(msg, "error-option", json_object_new_string(line));
		}
		printf("Configuration data: ");
		getline(&line, &len, stdin);
		line[(strlen(line) - 1)] = 0;
		json_object_object_add(msg, "config", json_object_new_string(line));
	} else if (strcmp(argv[1], "get") == 0) {
		/*
		 * NETCONF <get>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_GET));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
		printf("Filter: ");
		getline(&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		if (strlen(line) > 0) {
			json_object_object_add(msg, "filter", json_object_new_string(line));
		}
	} else if (strcmp(argv[1], "get-config") == 0) {
		/*
		 * NETCONF <get-config>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_GETCONFIG));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
		printf("Source (running|startup|candidate): ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "source", json_object_new_string(line));
		printf("Filter: ");
		getline(&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		if (strlen(line) > 0) {
			json_object_object_add(msg, "filter", json_object_new_string(line));
		}
	} else if (strcmp(argv[1], "kill-session") == 0) {
		/*
		 * NETCONF <kill-session>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_KILL));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
		printf("Kill session with ID: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session-id", json_object_new_string(line));
	} else if (strcmp(argv[1], "lock") == 0) {
		/*
		 * NETCONF <lock>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_LOCK));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
		printf("Target (running|startup|candidate): ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "target", json_object_new_string(line));
	} else if (strcmp(argv[1], "unlock") == 0) {
		/*
		 * NETCONF <unlock>
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_UNLOCK));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
		printf("Target (running|startup|candidate): ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "target", json_object_new_string(line));
	} else if (strcmp(argv[1], "info") == 0) {
		/*
		 * Get information about NETCONF session
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_INFO));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
	} else if (strcmp(argv[1], "generic") == 0) {
		/*
		 * Generic NETCONF request
		 */
		msg = json_object_new_object();
		json_object_object_add(msg, "type", json_object_new_int(MSG_GENERIC));
		printf("Session: ");
		getline (&line, &len, stdin);
		line[(strlen(line)-1)] = 0;
		json_object_object_add(msg, "session", json_object_new_string(line));
		printf("NETCONF <rpc> content: ");
		getline(&line, &len, stdin);
		line[(strlen(line) - 1)] = 0;
		json_object_object_add(msg, "content", json_object_new_string(line));
	} else {
		/*
		 * Unknown request
		 */
		fprintf(stderr, "Unknown command %s\n", argv[1]);
		close(sock);
		return (EXIT_FAILURE);
	}

	/* send the message */
	if (msg != NULL) {
		msg_text = json_object_to_json_string(msg);

		if (json_object_object_get(msg, "pass") == NULL) {
			/* print message only if it does not contain password */
			printf("Sending: %s\n", msg_text);
		}
		send(sock, msg_text, strlen(msg_text) + 1, 0);

		json_object_put(msg);
	} else {
		close(sock);
		return (EXIT_FAILURE);
	}

	len = recv(sock, buffer, BUFFER_SIZE, 0);
	if (len > 0) {
		reply = json_tokener_parse(buffer);
	}
	printf("Received:\n");
	if (reply == NULL) {
		printf("(null)\n");
	} else {
		json_object_object_foreach(reply, key, value) {
			printf("Key: %s, Value: ", key);
			switch (json_object_get_type(value)) {
			case json_type_string:
				printf("%s\n", json_object_get_string(value));
				break;
			case json_type_int:
				printf("%d\n", json_object_get_int(value));
				break;
			case json_type_array:
				printf("\n");
				alen = json_object_array_length(value);
				for (i = 0; i < alen; i++) {
					printf("\t(%d) %s\n", i, json_object_get_string(json_object_array_get_idx(value, i)));
				}
				break;
			default:
				printf("\n");
				break;
			}
		}
		json_object_put(reply);
	}
	close(sock);
	free(line);

	return (EXIT_SUCCESS);
}
