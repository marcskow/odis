#!/bin/bash

echo "Running active-firewall installer. Ubuntu distribution."

apt-get update
apt-get install libpcap-dev bison flex
apt-get install snort

apt install python3

echo "Installing snort rules and configuration."
rm /etc/snort/rules/local.rules
cp ./local.rules /etc/snort/rules/local.rules

rm /etc/snort/snort.conf
cp ./snort.conf /etc/snort/snort.conf

echo "Installation completed."
