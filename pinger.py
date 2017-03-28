#!/usr/bin/env python3

import argparse
import sys
import os
import select
import signal
import socket


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


if __name__ == '__main__':
    main()
