#!/usr/bin/env python3

import argparse
import sys
import os
import select
import signal
import socket


class Pinger(object):
    """Representation of the ping utility tool"""

    def __init__(self, args):
        self.logfile = args.logfile
        self.count = args.count
        self.payload = args.payload
        self.dst = args.dst

        self.stats = {
            'pkts_sent': 0,
            'pkts_rcvd': 0,
            'min_time': 999999999,
            'max_time': 0,
            'tot_time': 0
        }

    def display_stats(self):
        """
        Dump the stats upon ping completion or 'CTRL-C'
        """
        pass

    def ping(self):
        """
        Wrapper function around the entire 'ping' utility
        """
        print('Pinging {} with {} bytes of data "{}"'.format(
            socket.gethostbyname(self.dst), len(self.payload.encode()), self.payload))

        # just in case user didn't pass in IP address
        self.dst = socket.gethostbyname(self.dst)

        # send 'count' ICMP echo requests
        for i in range(self.count):
            self.send_one()

    def send_one(self):
        """
        Function that focuses on a single ICMP echo + reply transaction
        """
        print('ping!')

    def _send(self):
        """
        Function that focuses on send part of ping transaction
        """
        pass

    def _receive(self):
        """
        Function that focuses on receive part of ping transaction
        """
        pass


def main():
    parser = argparse.ArgumentParser(
        description='Implementation of ping utility tool using raw sockets'
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
        help='number of ping packets to send'
    )
    parser.add_argument(
        '-p', '--payload',
        dest='payload',
        required=True,
        help='string to include in the payload of ping packet'
    )
    parser.add_argument(
        '-d', '--dst',
        dest='dst',
        required=True,
        help='destination IP for the ping packet'
    )

    # Check if no args provided at all
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    pinger = Pinger(args)
    pinger.ping()


if __name__ == '__main__':
    main()
