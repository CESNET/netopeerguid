#!/bin/bash

if which apt-get >/dev/null 2>/dev/null; then
sudo apt-get update -qq -y
sudo apt-get install -qq -y git libjson-c-dev libapr1-dev libaprutil1-dev libxml2-dev apache2-dev pkg-config libtool cmake libtool cmake libxslt1-dev libcurl4-openssl-dev
wget http://security.ubuntu.com/ubuntu/pool/main/j/json-c/libjson-c-dev_0.11-3ubuntu1.2_amd64.deb http://security.ubuntu.com/ubuntu/pool/main/j/json-c/libjson-c2_0.11-3ubuntu1.2_amd64.deb
sudo dpkg -i ./libjson-c-dev_0.11-3ubuntu1.2_amd64.deb libjson-c2_0.11-3ubuntu1.2_amd64.deb
else
sudo yum install -y git json-c-devel apr-devel apr-util-devel libxml2-devel httpd-devel pkg-config libtool cmake libxslt-devel curl-devel
fi

(
wget -q https://red.libssh.org/attachments/download/107/libssh-0.6.4.tar.gz&&
tar -xf libssh-0.6.4.tar.gz&&mkdir lssh&&cd lssh&&cmake ../libssh-0.6.4&&sudo make install
)

(
git clone git://github.com/cejkato2/libwebsockets lws&&mkdir lws/b&&cd lws/b&&cmake ..&&sudo make install
)

(
git clone git://github.com/CESNET/libnetconf&&cd libnetconf&&./configure&&sudo make install
)

(
git clone git://github.com/mbj4668/pyang&&cd pyang&&sudo python setup.py install
)

