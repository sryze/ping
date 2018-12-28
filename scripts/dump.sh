#!/bin/sh

tcpdump -x -vvv -r ping.pcap | less
