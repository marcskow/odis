#!/usr/bin/env python3

import datetime
import os
import queue
import re
import sys
import threading
import time

ICMP_PING_NMAP_LIFETIME = 5


class IpTablesEntry:
    def __init__(self, rule, timestamp, lifetime=10):
        self.rule = rule
        self.timestamp = timestamp
        self.lifetime = lifetime


entryQueue = queue.Queue()


def detect(message):
    m = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3} -> ([0-9]{1,3}\.){3}[0-9]{1,3}", message)
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

        entryQueue.put(IpTablesEntry(iprule, datetime.datetime.now(), ICMP_PING_NMAP_LIFETIME))

        print(f"Adding /sbin/iptables -A {iprule}")
        os.system(f"/sbin/iptables -A {iprule}")


def cleaner():
    while True:
        while not entryQueue.empty():
            entry = entryQueue.get()
            if entry.timestamp < datetime.datetime.now() - datetime.timedelta(seconds=entry.lifetime):
                print(f"Removing /sbin/iptables -D {entry.rule}")
                os.system(f"/sbin/iptables -D {entry.rule}")
            else:
                entryQueue.put(entry)
                break
        time.sleep(20)


for stdLine in sys.stdin:
    thread = threading.Thread(target=cleaner, args=())
    thread.daemon = True
    thread.start()

    process(stdLine)
