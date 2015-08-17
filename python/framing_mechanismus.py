#!/usr/bin/python3
# -*- coding: utf-8 -*-
#python framin mechanismus for incomming message
import socket
import sys 
import os
import json
import threading
import errno
from enum import Enum

MAX_SOCKET_CL = 10
SOCKET_FILENAME = '/tmp/python_unix_sockets_example'
PORT = 8888
DECODE = 'UTF-8'

class MSG_TYPE(Enum):
    REPLY_OK = 0
    REPLY_DATA = 1
    REPLY_ERROR = 2
    REPLY_INFO = 3
    MSG_CONNECT = 4
    MSG_DISCONNECT = 5
    MSG_GET = 6
    MSG_GETCONFIG = 7
    MSG_EDITCONFIG = 8
    MSG_COPYCONFIG = 9
    MSG_DELETECONFIG = 10
    MSG_LOCK = 11
    MSG_UNLOCK = 12
    MSG_KILL = 13
    MSG_INFO = 14
    MSG_GENERIC = 15
    MSG_GETSCHEMA = 16
    MSG_RELOADHELLO = 17
    MSG_NTF_GETHISTORY = 18
    MSG_VALIDATE = 19

def get_framed_message(client):
    #client.setblocking(0)
    # read json in chunked framing
    buffer_len = 0
    buffer = ""
    c = ""
    i = chunk_len = 0
    chunk_len_str = ""
    try:
        while True:
            # read chunk length
            c = client.recv(1)
            # print("Precetl jsem c: " + c.decode(DECODE))
            if c.decode(DECODE) != '\n' or len(c)!=1: # len(c)!=1
                buffer = None
                break
            c = client.recv(1)
            if (c.decode(DECODE) != '#' or len(c)!=1):
                buffer = None
                break
            i = 0;
            chunk_len_str = ""

            while True:
                c = client.recv(1)
                #print(c.decode(DECODE))
                if len(c)==1 and (c.decode(DECODE) == '#' or c.decode(DECODE).isdigit()):
                    if i == 0 and c.decode(DECODE) == '#':
                        c = client.recv(1)
                        if len(c) != 1 or c.decode(DECODE) != '\n':
                            # end but invalid
                            buffer = None
                        # return buffer, end of message
                        return buffer
                    chunk_len_str += c.decode(DECODE)
                    i += 1
                    if i == 11:
                        print('Message is too long, buffer for length is not big enought!!!!!')
                        chunk_len_str = ""
                        break
                else:
                    break

            try:
                chunk_len = int(0 if chunk_len_str == "" else chunk_len_str)
            except ValueError:
                 buffer = None
                 break
            if c.decode(DECODE) != '\n' or chunk_len == 0:
                buffer = None
                break
            c = client.recv(chunk_len)
            if len(c) != chunk_len:
                buffer = None
                break
            buffer_len += len(c)
            buffer += c.decode(DECODE)

        return buffer

    except ValueError:
        # error 10035 is no data available, it is non-fatal
        raise Exception('Unexpected error:', sys.exc_info()[0])
        #if errorCode != 10035:
        #    print ('Non-fatal')
        #else:
        #    print ('No data available!')

class thread_routine(threading.Thread):
    def __init__(self, client_sock):
        threading.Thread.__init__(self)
        msg = ""
        self.client = client_sock


    def run(self):
        msg = get_framed_message(self.client)
        print(self.getName() + ": Message was: " + str(msg))
        #self.client.close()

        if not msg:
            # close client's socket (it's probably already closed by client)
            self.client.close()
            return

        json_data=json.loads(msg)
        print(json_data)
        #json_string = json.dumps(j,sort_keys=True)
        try:
            operation=int(json_data["type"])
        except ValueError:
            self.client.close()
            raise Exception("Unknow operation type.")
        except KeyError:
            self.client.close()
            raise Exception("KeyError, data has not 'type'")

        if operation == -1:
            print("Missing operation type form frontend.")
            self.send_back(msg)

        #print (self.getName() + ": Number of the operation(type): " + str(j["type"]))
        self.do_operation(operation, json_data)
        self.send_back(msg)

    # rozhodnuti o jakou operaci se jedna a ucinneni dane operace
    def do_operation(self, operation, request):
        reply = ""
        operation_name = MSG_TYPE(operation).name
        if operation_name == "MSG_CONNECT":
            #reply = handle_op_connect(request)
            print("Jedna se o operaci MSG_CONNECT")
        elif operation_name == "MSG_GET":
            print("Jedna se o operaci MSG_GET")
        elif operation_name == "MSG_GETCONFIG":
            print("Jedna se o operaci MSG_GETCONFIG")
        elif operation_name == "MSG_GETSCHEMA":
            print("Jedna se o operaci MSG_GETSCHEMA")
        elif operation_name == "MSG_EDITCONFIG":
            print("Jedna se o operaci MSG_EDITCONFIG")
        elif operation_name == "MSG_COPYCONFIG":
            print("Jedna se o operaci MSG_COPYCONFIG")
        elif operation_name == "MSG_DELETECONFIG" or operation_name == "MSG_LOCK" or operation_name == "MSG_UNLOCK":
            print("Jedna se o operaci MSG_DELETECONFIG nebo MSG_LOCK nebo MSG_UNLOCK")
        elif operation_name == "MSG_KILL":
            print("Jedna se o operaci MSG_KILL")
        elif operation_name == "MSG_DISCONNECT":
            print("Jedna se o operaci MSG_DISCONNECT")
        elif operation_name == "MSG_RELOADHELLO":
            print("Jedna se o operaci MSG_RELOADHELLO")
        elif operation_name == "MSG_INFO":
            print("Jedna se o operaci MSG_INFO")
        elif operation_name == "MSG_GENERIC":
            print("Jedna se o operaci MSG_GENERIC")
        elif operation_name == "MSG_NTF_GETHISTORY":
            print("Jedna se o operaci MSG_NTF_GETHISTORY")
        elif operation_name == "MSG_VALIDATE":
            print("Jedna se o operaci MSG_VALIDATE")
        else:
            print("Unknown mod_netconf operation requested " + str(operation))

    # poslani prichozich dat nazpet odesilateli
    def send_back(self, message):
        len_msg=len(message)
        data=bytes("\n#"+str(len_msg)+"\n"+message+"\n##\n", DECODE)
        self.client.send(data)
        self.client.close()

if __name__ == '__main__':
    thread_list = []

    # Make sure the socket does not already exist, if exist - remove it
    if os.path.exists(SOCKET_FILENAME):
        os.remove(SOCKET_FILENAME)

    # create listening UNIX socket to accept incoming connections
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except socket.error as ERROR_msg:
        raise Exception('Creating socket failed. Error message: ' + str(ERROR_msg))

    # bind the socket 
    try:
        s.bind(SOCKET_FILENAME)
    except socket.error as ERROR_msg:
        if ERROR_msg.errno == errno.EADDRINUSE:
            raise Exception('mod_netconf socket address already in use.')
        raise Exception('Binding socket failed. Error message: ' + str(ERROR_msg))

    # Listen for incoming comections
    try:
        s.listen(MAX_SOCKET_CL)
    except socket.error as ERROR_msg:
        raise Exception('Setting up listen socket failed. Error code: ' + str(ERROR_msg))

    print ('Listening at: ',s.getsockname())

    while True:
        # wait for a connection
        print ('Waiting for a connection.')
        (connection, client_address) = s.accept()
        print('Connection from: ' + str(client_address))
        new_thread = thread_routine(connection)
        print (new_thread.getName())
        thread_list.append(new_thread)
        new_thread.start()

        for thr in thread_list:
            if not thr.isAlive():
                thr.join()
                thread_list.remove(thr)
                
    for x in thread_list:
        x.join()
    del thread_list[:]

    s.close()



