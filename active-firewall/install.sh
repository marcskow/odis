#!/bin/bash

echo "Running active-firewall installer. Ubuntu distribution."

apt-get update
apt-get install libpcap-dev bison flex
apt-get install snort

apt install python3
