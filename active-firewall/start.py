#!/usr/bin/env python3

import sys
import re
import os
import datetime

timestamps = []
rules = []

def detect(line):
    m = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3} -> ([0-9]{1,3}\.){3}[0-9]{1,3}", line)
    if m is not None:
        print(m.group())
        s = m.group()
        return s.split(" -> ")[0]

def process(line):
    if "ICMP PING NMAP" in line:
        print(line)
        print("Port scanning detected.")
        source = detect(line)
        print("Attacker address: ")
        print(source)

        iprule = f"INPUT -s {source} -j DROP"
        
        rules.append(iprule)
        timestamps.append(datetime.datetime.now())
        
        os.system(f"/sbin/iptables -A {iprule}")
        
def cleaner():
    for idx, timestamp in enumerate(timestamps):
        if timestamp < datetime.datetime.now() - timedelta(seconds=30):
            os.system("/sbin/iptables -D {rules[idx]}")

for line in sys.stdin:
    process(line)
