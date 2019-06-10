#!/bin/bash

snort -d -l /var/log/snort/ -h $1/24 -A console -c /etc/snort/snort.conf | ./src/start.py
