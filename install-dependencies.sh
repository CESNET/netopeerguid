#!/bin/bash

if which apt-get >/dev/null 2>/dev/null; then
sudo apt-get update -qq -y
sudo apt-get install -qq -y git libjson-c-dev pkg-config libtool cmake
wget http://security.ubuntu.com/ubuntu/pool/main/j/json-c/libjson-c-dev_0.11-3ubuntu1.2_amd64.deb http://security.ubuntu.com/ubuntu/pool/main/j/json-c/libjson-c2_0.11-3ubuntu1.2_amd64.deb
sudo dpkg -i ./libjson-c-dev_0.11-3ubuntu1.2_amd64.deb libjson-c2_0.11-3ubuntu1.2_amd64.deb
else
sudo yum install -y git json-c-devel pkg-config libtool cmake
fi

(
wget https://red.libssh.org/attachments/download/195/libssh-0.7.3.tar.xz && tar -xJf libssh-0.7.3.tar.xz && cd libssh-0.7.3 && mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr .. && make && sudo make install
)

(
git clone git://github.com/cejkato2/libwebsockets lws && mkdir lws/b && cd lws/b && cmake .. && sudo make install
)

(
git clone git://github.com/CESNET/libyang && cd libyang && cmake . && make && sudo make install
)

(
git clone git://github.com/CESNET/libnetconf2 && cd libnetconf2 && cmake . && make && sudo make install
)

