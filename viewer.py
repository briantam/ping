#!/usr/bin/env python3

import dpkt
import pcapy
import sys
import socket
import argparse


def sniff_online(args):
    """
    Sniff the ICMP Echo packets that come through the given interface
    """
    print('DEBUG: sniffing device: ' + args.interface)

    try:
        sniffer = pcapy.open_live(args.interface, 65536, 1, 1)
        sniffer.setfilter('icmp')
    except Exception as e:
        print(e)
        sys.exit(-1)

    if not args.count:
        count = True
    else:
        count = args.count

    while count:
        (header, packet) = sniffer.next()
        if header:
            eth = dpkt.ethernet.Ethernet(packet)
            # print(header)
            # print(packet)
            print('ETH')
            print(eth)

            # Make sure IPv4 is next protocol
            if isinstance(eth.data, dpkt.ip.IP):
                print('IP')
                ip = eth.data
                # Make sure ICMP is next protocol
                if isinstance(ip.data, dpkt.icmp.ICMP):
                    print('ICMP')
                    icmp = ip.data
                    # Make sure ICMP Echo is payload
                    if isinstance(icmp.data, dpkt.icmp.ICMP.Echo):
                        print('ICMP ECHO')
                        echo = icmp.data
                        print(echo)
                        print('-----------------------------DATA----------------------------')
                        print(header.getts())
                        print('%s > %s' % (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)))
                        print('Type: %d, Code: %d, Id: %d, Seq: %d, Data: %s'
                              % (icmp.type, icmp.code, echo.id, echo.seq, len(echo.data)))
                        print('-------------------------------------------------------------')
                        print()

                        if args.count:
                            count -= 1


def sniff_offline(args):
    print('Reading from pcap file:', args.read)


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

    # Capture packets!
    if args.interface:
        sniff_online(args)
    elif args.read:
        sniff_offline(args)


if __name__ == '__main__':
    main()
