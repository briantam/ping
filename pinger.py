#!/usr/bin/env python3

import argparse
import sys
import os
import select
import signal
import socket
import time


# ICMP Echo Constants (see RFC 792)
ICMP_ECHO_REQ = 8
ICMP_ECHO_REP = 0
ICMP_ECHO_CODE = 0


class Pinger(object):
    """Representation of the ping utility tool"""

    def __init__(self, args):
        self.logfile = args.logfile
        self.count = args.count
        self.payload = args.payload
        self.dst = args.dst

        self.id = os.getpid() & 0xFFFF    # cap to 16 bits

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
        print('Ping statistics for {}:'.format(self.dst))
        print(str(self.stats))

    def ping(self):
        """
        Wrapper function around the entire 'ping' utility
        """
        try:
            print('Pinging {} with {} bytes of data "{}"'.format(
                socket.gethostbyname(self.dst), len(self.payload.encode()), self.payload))

            # just in case user didn't pass in IP address
            self.dst = socket.gethostbyname(self.dst)

        except socket.gaierror as e:
            print('Unkown host: {} ({})'.format(self.dst, e.args[1]))
            sys.exit(0)

        # send 'count' ICMP echo requests
        for seq_num in range(self.count):
            self.send_one(seq_num)

            time.sleep(1)

        self.display_stats()

    def send_one(self, sequence_num):
        """
        Function that focuses on a single ICMP echo + reply transaction
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            if e.errno == 1:
                print('Error: must run program as root to use raw sockets.')
                sys.exit(0)
            raise

        print('ping' + str(sequence_num) + '!')


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
