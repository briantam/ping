#!/usr/bin/env python3

import argparse
import sys
import os
import select
import signal
import socket
import time
import struct
import array


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

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            if e.errno == 1:
                print(e.args[1] + ' - must run program as root to use raw sockets.')
                sys.exit(0)
            raise

    def display_stats(self):
        """
        Dump the stats upon ping completion or 'CTRL-C'
        """
        print('Ping statistics for {}:'.format(self.dst))
        print(str(self.stats))

    def ping(self):
        """
        Driver function behind the entire 'ping' utility
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

        self.sock.close()
        self.display_stats()

    def send_one(self, sequence_num):
        """
        Send a single ICMP echo request and receive the echo reply
        @return delay (i.e., RTT)
        """
        sent_time = self._send(sequence_num)

        print('ping' + str(sequence_num) + ' ' + str(sent_time))

    def _send(self, sequence_num):
        """
        Send one echo request
        @return transmission time
        """
        checksum = 0

        # Create a temp ICMP header with 0 as checksum
        header = struct.pack('!BBHHH', ICMP_ECHO_REQ, ICMP_ECHO_CODE,
                             checksum, self.id, sequence_num)
        payload = self.payload.encode()
        checksum = self._compute_checksum(header + payload)

        # print(struct.unpack('!BBHHH', header))
        # print(self.id)

        # Recreate the ICMP header with calculated checksum
        header = struct.pack('!BBHHH', ICMP_ECHO_REQ, ICMP_ECHO_CODE,
                             checksum, self.id, sequence_num)
        packet = header + payload

        # Send off the ICMP echo request
        sent_time = time.time()
        try:
            self.sock.sendto(packet, (self.dst, 1))
        except socket.error as e:
            raise e

        return sent_time

    def _receive(self):
        """
        Receive one echo reply
        """
        pass

    def _compute_checksum(self, packet):
        """
        Compute the checksum for the ICMP packet, per RFC 792 + RFC 1071
        @return checksum of header + payload
        """
        # creds to scapy's implementation
        if len(packet) % 2 == 1:
            packet += bytes('\0', 'utf-8')
        s = sum(array.array('H', packet))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        s = ~s & 0xFFFF

        # little to big endian (host -> network)
        return socket.htons(s)


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
