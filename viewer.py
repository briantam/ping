#!/usr/bin/env python3

import dpkt
import pcapy
import sys
import socket
import argparse


def main():
    parser = argparse.ArgumentParser(
        description='Implementation of ICMP packet sniffer on an interface or pcap file'
    )
    parser.add_argument(
        '-l', '--logfile',
        dest='logfile',
        help='log file to write debug information to'
    )
    parser.add_argument(
        '-c', '--count',
        dest='count',
        type=int,
        default=3,
        help='print `count` number of packets and quit'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-i', '--int',
        dest='interface',
        help='interface to sniff ICMP echo packets on'
    )
    group.add_argument(
        '-r', '--read',
        dest='read',
        help='pcap file to print ICMP echo packets from'
    )

    # Check if no args provided at all
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()


if __name__ == '__main__':
    main()
