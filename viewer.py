#!/usr/bin/env python3

import dpkt
import pcapy
import sys
import signal
import socket
import argparse


def sniff_online(args):
    """
    Sniff the ICMP Echo packets that come through the given interface
    """
    print('viewer: listening on ' + args.interface)

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
            tts = header.getts()
            ret = parse_ICMP_Echo(tts[0] + tts[1] / 1000000, packet)

            if ret and args.count:
                count -= 1


def sniff_offline(args):
    """
    Sniff the ICMP Echo packets from the given pcap file
    """
    print('viewer: reading from ' + args.read)

    try:
        with open(args.read, 'rb') as f:
            reader = dpkt.pcap.Reader(f)
            reader.dispatch(0 if not args.count else args.count, parse_ICMP_Echo)
    except FileNotFoundError as e:
        print('File \'{}\' not found.'.format(args.read))
        sys.exit(1)


def parse_ICMP_Echo(timestamp, packet):
    """
    Parse the raw bytes of a given packet and prints info only if ICMP Echo type
    @param timestamp - float of the timestamp in epoch time
    @param packet - the bytes buffer/obj. representing the packet
    @return - True if packet info was extracted, False otherwise
    """
    eth = dpkt.ethernet.Ethernet(packet)

    # Make sure IPv4 is next protocol
    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        # Make sure ICMP is next protocol
        if isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data
            # Make sure ICMP Echo is payload
            if isinstance(icmp.data, dpkt.icmp.ICMP.Echo):
                echo = icmp.data

                if icmp.type == dpkt.icmp.ICMP_ECHO:
                    echo_type_str = 'request'
                elif icmp.type == dpkt.icmp.ICMP_ECHOREPLY:
                    echo_type_str = 'reply'
                else:
                    return False

                ip_src = socket.inet_ntoa(ip.src)
                ip_dst = socket.inet_ntoa(ip.dst)

                print('{:.6f} '.format(timestamp), end='')
                print('{} > {}: '.format(ip_src, ip_dst), end='')
                print('ICMP echo {}, id {}, seq {}, length {}'
                      .format(echo_type_str, echo.id, echo.seq, len(echo.data)))
                return True

    return False


def signal_handler(signum, frame):
    """
    Handle 'CTRL-C' by gracefully closing without traceback
    """
    sys.exit(0)


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

    # Override signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Capture packets!
    if args.interface:
        sniff_online(args)
    elif args.read:
        sniff_offline(args)


if __name__ == '__main__':
    main()
