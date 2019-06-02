#!/bin/bash

echo "Running anti port-scanning configuration"
./aportscanning.sh

echo "Running anti brute-force configuration"
./abruteforce.sh

echo "Running anti ddos configuration"
./addos.sh
