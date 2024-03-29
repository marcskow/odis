#!/usr/bin/env python3

import datetime
import io
import os
import queue
import re
import subprocess
import sys
import threading
import time

# patterns
IP_REGEX = r"(\d{1,3}\.){3}\d{1,3}"
OPTIONAL_PORT_REGEX = r"(:\d{1,5})+"
IP_PORT_REGEX = IP_REGEX + OPTIONAL_PORT_REGEX

# constants
DEFAULT_RULE_LIFETIME = 60
PORT_SCANNING_LIFETIME = 30
CLEANER_INTERVAL = 15


# data classes
class Rule:
    def __init__(self, protocol="tcp", lifetime=DEFAULT_RULE_LIFETIME):
        self.protocol = protocol
        self.lifetime = lifetime

    def as_iptables_entry(self, ip):
        port = f" --dport {ip.port}" if ip.port else ""

        return f"INPUT" \
            f" -p {self.protocol}" \
            f"{port}" \
            f" -s {ip.address} -j DROP"


class Ip:
    def __init__(self, address, port):
        self.address = address
        self.port = port

    def __str__(self) -> str:
        return f"{self.address}" + f":{self.port}" if self.port else ""


class ActiveFirewallConfiguration:
    def __init__(self, attack, message=None, rule=Rule()):
        self.attack = attack
        self.message = attack if message is None else message
        self.rule = rule


class IpTablesEntry:
    def __init__(self, rule, timestamp, lifetime=10):
        self.rule = rule
        self.timestamp = timestamp
        self.lifetime = lifetime


# data, attacks configurations
entry_queue = queue.Queue()
configurations = [
    ActiveFirewallConfiguration(
        "ICMP PING NMAP",
        "Port scanning detected.",
        Rule(protocol="icmp", lifetime=PORT_SCANNING_LIFETIME)
    ),
    ActiveFirewallConfiguration(
        "Possible TCP DoS",
        "TCP DoS detected."
    ),
    ActiveFirewallConfiguration(
        "Ping of Death Detected"
    ),
    ActiveFirewallConfiguration(
        "Land attack detected"
    ),
    ActiveFirewallConfiguration(
        "GET Request flood attempt"
    ),
    ActiveFirewallConfiguration(
        "UDP flood attack detected"
    )
]
dangerous_ips = {}


# implementation
def check_if_already_exists(rule, ip):
    proc = subprocess.Popen(['iptables-save'], stdout=subprocess.PIPE)

    match = False
    for line in io.TextIOWrapper(proc.stdout, encoding="utf-8"):
        if not line:
            break
        match = ((f"-s {ip.address}" in line)
                 and (f"--dport {ip.port}" in line if ip.port else "--dport" not in line)
                 and (f"-p {rule.protocol}" in line if rule.protocol else "-p" not in line))
        if match:
            break

    return match


def source_post_process(source):
    ip = re.search(IP_REGEX, source).group()
    port = re.search(OPTIONAL_PORT_REGEX, source).group().replace(":", "")
    return Ip(ip, port)


def detect(message):
    m = re.search(IP_PORT_REGEX + " -> " + IP_PORT_REGEX, message)
    if m is not None:
        source_destination = m.group().split(" -> ")[0]
        source = source_post_process(source_destination)
        return source


def increase_level_of_danger(source):
    if source.address not in dangerous_ips:
        dangerous_ips[source.address] = 0
        return source
    else:
        level_of_danger = dangerous_ips[source.address]
        if level_of_danger >= 2:
            return Ip(source.address, None)
        else:
            dangerous_ips[source.address] = dangerous_ips[source.address] + 1
            return source


def process(line):
    match = next((config for config in configurations if config.attack in line), None)

    if match is not None:
        prev_source = detect(line)
        source = increase_level_of_danger(prev_source)

        rule = match.rule.as_iptables_entry(source)

        if not check_if_already_exists(match.rule, source):
            print()
            if prev_source.port and not source.port:
                print(f"Danger level too high. Whole Ip will be blocked instead of one port for {source.address}.")
            print(match.message)
            print(f"Adding /sbin/iptables -A {rule}")
            entry_queue.put(IpTablesEntry(rule, datetime.datetime.now(), match.rule.lifetime))
            os.system(f"/sbin/iptables -A {rule}")


def cleaner():
    while True:
        while not entry_queue.empty():
            entry = entry_queue.get()
            if entry.timestamp < datetime.datetime.now() - datetime.timedelta(seconds=entry.lifetime):
                print(f"Removing /sbin/iptables -D {entry.rule}")
                os.system(f"/sbin/iptables -D {entry.rule}")
            else:
                entry_queue.put(entry)
                break
        time.sleep(CLEANER_INTERVAL)


for stdLine in sys.stdin:
    thread = threading.Thread(target=cleaner, args=())
    thread.daemon = True
    thread.start()

    process(stdLine)
