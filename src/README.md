# How To Setup Service

- netopeerguid compilation requires libjson-devel, libnetconf-devel, and libyang packages.

- run following commands in this directory
```
$ make
$ make install
```
- netopeerguid runs as a service daemon. It listens on the UNIX socket (/var/run/netopeerguid.sock) for communication with frontend and on TCP socket 8080 for notifications over WebSocket. Start the service by

```
$ service netopeerguid.rc start
```

If there is any problem with connection to the UNIX socket, please check file permissions.

## List of dependencies

* json-c
* libnetconf
* libyang

(with development packages)

Optionally: libwebsockets

# netopeerguid Message Format

UNIX socket (with default path /tmp/netopeerguid.sock) is used for communication with netopeerguid. Messages are formated using JSON and encoded using

Chunked Framing Mechanism described in RFC6242 (http://tools.ietf.org/html/rfc6242#section-4.2) with the following content.

Client is free to send multiple requests when the communication socket to the netopeerguid is opened.

## Data types:

sJSON: string representation of a JSON object

SID: generated unique session identifier (unsigned integer starting with 1)

### Replies

Replies are in the format:
```
{
    "<SID#1>": {
        <reply>
    },
    "<SID#2>": {
        <reply>
    },
    …
    "<SID#last>": {
        <reply>
    }
}
```
Reply format is defined below.

#### Reply

##### 1) OK
* key: type (int), value: 0

##### 2) DATA

* key: type (int), value: 1
* key: data (sJSON)

##### 3) ERROR

* key: type (int), value: 2
* key: error-message (string)

Optional:

* key: error-tag (string)
* key: error-type (string)
* key: error-severity (string)
* key: error-app-tag (string)
* key: error-path (string)
* key: bad-attribute (string)
* key: bad-element (string)
* key: bad-namespace (string)
* key: session-id (int)

##### 4) INFO

* key: type (int), value: 3
* key: sid (int), value: session ID
* key: version (string), value: NETCONF protocol version
* key: host (string), value: hostname of the NETCONF server
* key: port (string), value: port of the NETCONF server
* key: user (string), value: username of the user holding the NETCONF session
* key: capabilities (array of strings), value: list of supported capabilities

Example reply to connect:

```
{
    "<new-SID>": {
        "type": 0
    }
}
```

#### Requests

##### 1) Request to create NETCONF session (connect)

* key: type (int), value: 4
* key: user (string)

Optional:

* key: host (string), "localhost" if not specified
* key: port (string), "830" if not specified
* key: pass (string), value: plain text password, mandatory if "privatekey" is not set
* key: privatekey (string), value: filesystem path to the private key, if set, "pass" parameter s optional and changes into the pass for this private key

##### 2) Request to close NETCONF session (disconnect)

* key: type (int), value: 5
* key: sessions (array of ints), value: array of SIDs

##### 3) NETCONF <get> (returns merged data)

* key: type (int), value: 6
* key: sessions (array of ints), value: array of SIDs
* key: strict (bool), value: whether return error on unknown data

Optional:

* key: filter (string), value: xml subtree filter

##### 4) NETCONF <get-config> (returns array of responses merged with schema)

* key: type (int), value: 7
* key: sessions (array of ints), value: array of SIDs
* key: source (string), value: running|startup|candidate
* key: strict (bool), value: whether return error on unknown data

Optional:

* key: filter (string), value: xml subtree filter

##### 5) NETCONF <edit-config>

* key: type (int), value: 8
* key: sessions (array of ints), value: array of SIDs
* key: target (string), value: running|startup|candidate
* key: configs (array of sJSON, with the same order as sessions), value: array of edit onfiguration data according to NETCONF RFC for each session

Optional:

* key: source (string), value: config|url, default value: config
* key: default-operation (string), value: merge|replace|none
* key: error-option (string), value: stop-on-error|continue-on-error|rollback-on-error
* key: uri-source (string), required when "source" is "url", value: uri
* key: test-option (string), value: notset|testset|set|test, default value: testset

##### 6) NETCONF <copy-config>

* key: type (int), value: 9
* key: sessions (array of ints), value: array of SIDs
* key: source (string), value: running|startup|candidate|url|config
* key: target (string), value: running|startup|candidate|url

Optional:

* key: uri-source (string), required when "source" is "url", value: uri
* key: uri-target (string), required when "target" is "url", value: uri
* key: configs (array of sJSON, with the same order as sessions), required when "source" is config”, value: array of new complete configuration data for each session,

##### 7) NETCONF <delete-config>

* key: type (int), value: 10
* key: sessions (array of ints), value: array of SIDs
* key: target (string), value: running|startup|candidate|url

Optional:

* key: url (string), value: target URL

##### 8) NETCONF <lock>

* key: type (int), value: 11
* key: sessions (array of ints), value: array of SIDs
* key: target (string), value: running|startup|candidate

##### 9) NETCONF <unlock>

* key: type (int), value: 12
* key: sessions (array of ints), value: array of SIDs
* key: target (string), value: running|startup|candidate

##### 10) NETCONF <kill-session>

* key: type (int), value: 13
* key: sessions (array of ints), value: array of SIDs
* key: session-id (int), value: SID of the session to kill

##### 11) Provide information about NETCONF session

* key: type (int), value: 14
* key: sessions (array of ints), value: array of SIDs

##### 12) Perform generic operation not included in base NETCONF

* key: type (int), value: 15
* key: sessions (array of ints), value: array of SIDs
* key: contents (array of sJSON with same index order as sessions array), value: array of sJSON ata as content of the NETCONF's <rpc> envelope

##### 13) get-schema

* key: type (int), value: 16
* key: sessions (array of ints), value: array of SIDs
* key: identifiers (array of strings with same index order as sessions array), value: array of chema identifiers

Optional:

* key: format (string), value: format of the schema (yin or yang)

##### 14) reloadhello Update hello message of NETCONF session

* key: type (int), value: 17
* key: sessions (array of ints), value: array of SIDs

##### 15) notif_history Provide list of notifications from past.

* key: type (int), value: 18
* key: sessions (array of ints), value: array of SIDs
* key: from (int64), value: start time in history
* key: to (int64), value: end time

##### 16) validate Validate datastore or url

* key: type (int), value: 19
* key: sessions (array of ints), value: array of SIDs
* key: target (string), value: running|startup|candidate|url

Required when target is "url":

* key: url (string), value: URL of datastore to validate

#### Enumeration of Message type (libnetconf)

```
	/* Enumeration of Message type (taken from mod_netconf.c) */

	const REPLY_OK				= 0;
	const REPLY_DATA			= 1;
	const REPLY_ERROR			= 2;
	const REPLY_INFO			= 3;
	const MSG_CONNECT			= 4;
	const MSG_DISCONNECT		= 5;
	const MSG_GET 				= 6;
	const MSG_GETCONFIG			= 7;
	const MSG_EDITCONFIG		= 8;
	const MSG_COPYCONFIG		= 9;
	const MSG_DELETECONFIG		= 10;
	const MSG_LOCK 				= 11;
	const MSG_UNLOCK			= 12;
	const MSG_KILL				= 13;
	const MSG_INFO				= 14;
	const MSG_GENERIC			= 15;
	const MSG_GETSCHEMA			= 16;
	const MSG_RELOADHELLO		= 17;
	const MSG_NTF_GETHISTORY	= 18;
	const MSG_VALIDATE			= 19;

	/* Enumeration of Message type - New for libyang */
	const SCH_QUERY				= 100;
	const SCH_MERGE				= 101;
```

#### 1) Query schema node by XPATH

* key: type (int), value: 100
* key: sessions (array of ints), value: array of SIDs
* key: filters (array of strings with same index order as sessions), value: array of XPath (with "prefix" = module name) values of target node in schema (start with ‘/’) or module names

Optional:

* key: load_children(boolean, default = false), value: if set to true, children schema information will be loaded too (blue part in example 1). Otherwise only value "$@name": {'children': [...]} will be loaded.

##### 1. Example response for "/ietf-interfaces:interfaces":

(partialy based on https://tools.ietf.org/html/draft-ietf-netmod-yang-json-05#appendix-A)
```
{
	"$@ietf-interfaces:interfaces": {
		"eltype": "leaf",
		"config": "false",
		"type": "enumeration",
		"enumval": [int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string],
		"description": "The data type of the parameters argument.,
		"mandatory": "false",
		"iskey": "false",
		"children": [interface, interface-state]
	},

"ietf-interfaces:interfaces": {
		"$@interface": {
			"eltype": "list",
			"config": "true",
			"type": "enumeration",
			"iskey": "false"
		},
		"$@interface-state": { ... }
	}
}
```

##### 2. Example response for "/ietf-interfaces:interfaces/interface":
```
{
	"$@interface": {
		"eltype": "list",
		"config": "true",
		"type": "enumeration",
		"iskey": "false"
	}
}
```

##### 3. Example response for "ietf-interfaces" without load_children:
```
{
	"$@@ietf-interfaces": {
		"yang-version": “1.0”,
		"namespace": "urn:ietf:params:xml:ns:yang:ietf-interfaces",
		"prefix": “if”,
		"imports": [
			{
				"name": “ietf-yang-types”,
				"prefix": “yang”
			}
		],
		"organization": "IETF NETMOD (NETCONF Data Modeling Language) …”,
		"contact": “WG Web:   <http://tools.ietf.org/wg/netmod/>...”,
		"description": "This module contains a collection of YANG definitions…”,
		"revision": "2014-05-08"
	}
}
```

#### 2) Merge given XML configuration with schema

* key: type (int), value: 101
* key: sessions (array of ints), value: array of SIDs
* key: configurations (array of sJSON with same index order as sessions array), value: array of clean sJSON configurations without schema information

## Merged format for schema

Each node of <get> or <get-config> request will be "merged" with schema in following scenario:

##### 1) each information from schema will be added as sibling of node as an attribute defined by **$@node_name**:

Example:
```
{
	"$@node_name": {
		"eltype": "list",
		"config": true,
		"type": "enumeration",
		"iskey": false
	}
}
```

##### 2) if node has some children defined in schema, these children will be defined as children array:

Example:
```
{
	"$@node_name": {
		"children": ["interface", "interface-state"]
	}
}
```

##### 3) if some attribute is reference to some user defined type, referenced value should be added too as JSON object - same result as defined in SCH_QUERY:

Example:
```
{
	"$@interface": {
		"eltype": "list",
		"config": "true",
		"type": "enumeration",
		"iskey": "false",
	},

	"interface": [
		{
		"$@type": {
			"typedef": {
				// same result as SCH_QUERY for this typedef
				"type": "uint8",
				"range": "0 .. 100",
				"description": "Percentage"
			}
		},
		"type": "iana-if-type:ethernetCsmacd"
		}
	]
}
```

##### 4) if some node is enumeration, available values will be defined as array

Example:
```
{
	"$@node_name": {
		"enumval": [int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string]
	}
}
```

##### 5) choice - case

	Example based on https://tools.ietf.org/html/rfc6020#section-7.9
```
{
	"$@transfer": {
		"eltype": "container",
		"config": "true",
		"choice": ["how"]
	},
	"transfer": {
		"$@how": {
			"eltype": "choice",
			"default": "interval",
			"cases": ["interval", "daily", "manual"]
		},
		"how": {
			"$@interval": {
				"eltype": "case",
				"children": ["interval"]
			},
			"$@daily": {
				"eltype": "case",
				"children": ["daily", "time-of-day"]
			}
			"$@manual": {
				"eltype": "case",
				"children": ["manual"]
			}
		},
		"$@interval": {
			"eltype": "leaf",
			"type": "uint16",
			"default": "30",
			"units": "minutes"
		},
		"$@daily": {
			"eltype": "leaf",
			"type": "empty"
		},
		"$@time-of-day": {
			"eltype": "leaf",
			"type": "string",
			"default": "1am",
			"units": "24-hour-clock"
		},
		"$@manual": {
			"eltype": "leaf",
			"type": "string"
		}
	}
}
```

## Complete merged JSON example:
```
{
	"$@ietf-interfaces:interfaces": {
		"eltype": "leaf",
		"config": "false",
		"type": "enumeration",
		"enumval": [int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string],
		"description": "The data type of the parameters argument.,
		"mandatory": "false",
		"iskey": "false",
		"children": ["interface", "interface-state"]
	},
	"ietf-interfaces:interfaces": {
		"$@interface": {
			"eltype": "list",
			"config": "true",
			"type": "enumeration",
			"iskey": "false",
		},
		"interface": [
			{
				"$@name": {
					"eltype": “leaf”,
					"config": "true",
					"type": "string"
				},
				"name": "eth0",
				"$@type": {
					"eltype": “leaf”,
					"config": “true”,
					"type": “link-load”,
					"typedef": { // just an example, this differs in the model
						"type": "uint8",
						"range": "0 .. 100",
						description "Percentage"
					}
				},
				"type": "iana-if-type:ethernetCsmacd",
				"$@enabled": {
					"eltype": “leaf”,
					"config": “true”,
					"type": "boolean"
				},
				"enabled": false
			},
			{
				"$@name": { ... }
				"name": "eth1",
				"$@type": { ... }
				"type": "iana-if-type:ethernetCsmacd",
				"$@enabled": { ... }
				"enabled": true,
				"$@ex-vlan:vlan-tagging": { ... }
				"ex-vlan:vlan-tagging": true
			}
		]
	},
	"$@ietf-interfaces:interfaces-state": {
			"eltype": "leaf",
			"config": "false",
			"type": "enumeration",
			"enumval": [int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string],
			"description": "The data type of the parameters argument.,
			"mandatory": "false",
			"iskey": "false"
		}
	"ietf-interfaces:interfaces-state": {
		...
	}
}
```

## Substatements definitions

**anyxml** - XML string which should be converted info JSON in mod_netconf (if it is possible) or in NetopeerGUI backend
```
{
	"$@data": {
		"eltype": “anyxml”
	},
	"data": {
		"root": {
			"node": "value"
		}
	}
}
```

---

**augment** - applied automatically in result

---

**bit**- type
```
{
	"bits": [
		{
			"name": “first-bit”,
			"position": 0
		},
		{
			"name": “second-bit”,
			"position": 1
		},
		...
	]
}
```

---

**case**
```
{
	"children": [“child1”, “child2”, …],
	"choice": [“choice1”, “choice2”, …]
}
```

---

**choice** - defined in example 5

---

**config**
```
{
	"config": true/false
}
```

---

**container** - defined in "eltype"
```
{
	"$@interface": {
		"eltype": "container"
	}
}
```

---

**default**
```
{
	"default": "default value of node"
}
```

---

**description**
```
{
	"description": "The text of description of node"
}
```

---

**enum** - values are transformed into "enumval"
```
{
	"$@ietf-interfaces:interfaces-state": {
		"type": "enumeration",
		"enumval": [int8, int16, int32, int64, uint8, uint16, uint32, uint64, float]
	}
}
```

---

**fraction-digits**
```
{
	"fraction-digits": 2
}
```

---

**grouping** - rendered in "uses" statement directly

---

**key**
```
{
	"$@list-name": {
		"eltype": "list"
		"keys": [“key-element-name”]
	}
}
```

---

**leaf**
```
{
	"$@leaf-name": {
		"eltype": "leaf",
		"iskey": true/false
	}
}
```

---

**leaf-list**
```
{
	"$@leaf-name": {
		"eltype": "leaf-list"
	}
}
```

---

**length** - renders same value as defined in schema
```
{
	"length": "1..255"
}
```

---

**list**
```
{
	"$@list-name": {
		"eltype": "list"
	},
	"list-name": {
		"$@leaf-name": {
			"eltype": “leaf”,
			...
		}
	}
}
```

---

**mandatory**
```
{
	"mandatory": "true/false"
}
```

---

**max-elements**
```
{
	"max-elements": number
}
```

---

**min-elements**
```
{
	"min-elements": number
}
```

---

**ordered-by**
```
{
	"order-by": “user/system”
}
```

---

**path** - if defined, target schema informations must be defined, even if data does not exists
```
{
	"$@target": { … },
	"$@node": {
		"eltype": “leafref”,
		"path": “path/to/target”
	}
}
```

---

**pattern**
```
{
	"pattern": ["[0-9a-fA-F]*"]
}
```

---

**position** - no semantical informations, see "bits" statement

---

**presence**
```
{
	"presence": “the meaning of presence in container”
}
```

---

**range**
```
{
	"range": "11..max"
}
```

---

**reference**
```
{
	"reference": "[RFC 3986](https://tools.ietf.org/html/rfc3986): Uniform Resource Identifier (URI): Generic Syntax"
}
```

---

**refine** - renders target automatically

---

**rpc** - rendered as any other data information with schema. In NetopeerGUI is rendered as a standalone tree. Output substatement is not needed in GUI.

```
{
	"$@rock-the-house": {
		"eltype": "rpc"
	},
	"rock-the-house": {
		"input": {
			"$@zip-code": {
				"eltype": “leaf”,
				"type": “string”
			}
			"zip-code": { … }
		}
	}
}
```

---

**status**
```
{
	"status": “current/deprecated/obsolete”
}
```

---

**type** - same value as defined in schema
```
{
	"type": “string”
}
```

---

**typedef** - defined in example 3

---

**union**
```
{
	"type": “union”,
	"types": [
		{
			(type1)
		},
		{
			(type2)
		},
		...
	]
}
```

**unique**
```
{
	"$@list-name": {
		"eltype": “list”,
		"unique": [“ip”, “port”]
	}
}
```

---

**units**
```
{
	"units": “string of the units”
}
```

---

**uses** - renders content of "grouping" statement directly

---

**must**
```
{
	"must": [“must-condition-1”, “must-condition-2”, …]
}
```

---

**when**
```
{
	"when": “when-condition”
}
```

---

**require-instance**
```
{
	"require-instance": true/false
}
```

---

**identity** - all values are transformed into "identityval"
```
{
	"ietf-interfaces:interfaces": {
		"interface": {
			"$@type": {
			"type": "identityref",
					"identityval": [interface-type, iana-if-type:iana-interface-type, iana-if-type:other, iana-if-type:regular1822, ...]
				}
			}
		}
	}
}
```

---

******extension****** - support for NACM extensions only
```
{
	"ext": “default-deny-write”/”default-deny-all”
}
```

---

Only a part of module information:

---

**contact**
```
{
	"contact": “contact information”
}
```

---

**organization**
```
{
	"organization": “organization information”
}
```

---

**namespace**
```
{
	"namespace": “model namespace”
}
```

---

**prefix**
```
{
	"prefix": “model prefix”
}
```

---

**revision**
```
{
	"revision": “last model revision date”
}
```

---

**revision-date** - part of import and include output

---

**yang-version**
```
{
	"yang-version": “1.0/1.1”
}
```

---

**import**
```
{
	"imports": [
		{
			"name": “import name”,
			"prefix": “import prefix”,
			"revision": “import revision date”
		}
	]
}
```

---

**include**
```
{
	"includes": [
		{
			"name": “include name”,
			"revision": “include revision date”
		}
	]
}
```

---

Not used (we don't need this information):

* "belongs-to"
* "deviate"
* "deviation"
* "error-app-tag"
* "error-message"
* "if-feature"
* "notification"
* "yin-element"
* "argument"



