#!/bin/bash

iptables -N ICMP-RATE-LIMIT
iptables -A INPUT -p icmp -j ICMP-RATE-LIMIT

iptables -A ICMP-RATE-LIMIT -m limit --limit 1/minute --limit-burst 5 -j ACCEPT
iptables -A ICMP-RATE-LIMIT -j DROP
