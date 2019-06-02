#!/bin/bash

iptables -t nat -A PREROUTING -i eth0 -p tcp -m tcp -m multiport --dports 1:21,23:79,81:65535 -j REDIRECT --to-ports 4444

apt-get update
apt-get install make
apt-get install g++
apt-get install unzip

wget https://github.com/drk1wi/portspoof/archive/master.zip

unzip master.zip

cd ./portspoof-master

./configure
make
make install

portspoof -c /usr/local/etc/portspoof.conf -s /usr/local/etc/portspoof_signatures -D

rm -rf ./master.zip ./portspoof-master
