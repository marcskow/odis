#!/usr/bin/env python3

import datetime
import os
import queue
import re
import sys
import threading
import time

# patterns
IP_REGEX = r"(\d{1,3}\.){3}\d{1,3}"
OPTIONAL_PORT_REGEX = r"(:\d{1,5})?"
IP_PORT_REGEX = IP_REGEX + OPTIONAL_PORT_REGEX

# constants
ICMP_PING_NMAP_LIFETIME = 5


# implementation
class ActiveFirewallConfiguration:
    def __init__(self, attack, message, rule):
        self.attack = attack
        self.message = message
        self.rule = rule


class IpTablesEntry:
    def __init__(self, rule, timestamp, lifetime=10):
        self.rule = rule
        self.timestamp = timestamp
        self.lifetime = lifetime


entryQueue = queue.Queue()
configurations = []


def source_post_process(source):
    return re.search(IP_REGEX, source).group()


def detect(message):
    m = re.search(IP_PORT_REGEX + " -> " + IP_PORT_REGEX, message)
    if m is not None:
        print(m.group())
        source = m.group().split(" -> ")[0]
        pp = source_post_process(source)
        return pp


def process(line):
    match = next((config for config in configurations if config.attack in line), None)

    if match is not None:
        print(line)
        print(match.message)

        source = detect(line)

        print(f"Attacker address: {source}")

        rule = match.rule.format(source)
        entryQueue.put(IpTablesEntry(rule, datetime.datetime.now(), ICMP_PING_NMAP_LIFETIME))

        print(f"Adding /sbin/iptables -A {rule}")
        os.system(f"/sbin/iptables -A {rule}")


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


configurations.append(ActiveFirewallConfiguration("ICMP PING NMAP", "Port scanning detected.", "INPUT -s {} -j DROP"))
configurations.append(ActiveFirewallConfiguration("Possible TCP DoS", "TCP DoS detected.", "INPUT -s {} -j DROP"))

for stdLine in sys.stdin:
    thread = threading.Thread(target=cleaner, args=())
    thread.daemon = True
    thread.start()

    process(stdLine)
