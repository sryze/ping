#!/bin/sh
sudo tcpdump -i en1 -w ping.pcap -v icmp
