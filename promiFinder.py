#!/usr/bin/env python

import scapy
import sys

def getAllIPs():
    """
    @return: list of tuples with (ip, netmask)
    """
    import netifaces
    addresses = []
    for ifname in netifaces.interfaces():
        if ifname not in ["lo"]:
            tmpAddresses = netifaces.ifaddresses(ifname)
            if netifaces.AF_INET in tmpAddresses:
                addresses += [(i['addr'], i['netmask']) for i in tmpAddresses[netifaces.AF_INET]]
    return addresses

def convert2cidr(ip, netmask):
    """
    @return: string of cidr representation for the given ip and netmask
    """
    nm = netmask.split(".")
    cidr = 0
    done = False
    for i in range(4):
        if done and nm[i] != "0":
            raise Exception("invalid netmask")
        else:
            binary = str(bin(int(nm[i])))[2:]
            splitted = binary.split('0')
            if not [e for e in splitted[1:] if e]:
                ones = splitted[0].count("1")
                cidr += ones
            else:
                raise Exception("invalid netmask")
            if ones != 8:
                done = True
    return "%s/%d" % (ip, cidr)



def sendArp(cidr):
    """
    @returns: list of response packets
    """
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:fe")/ARP(pdst=cidr),timeout=2)
    return ans.res

state = []
ips = getAllIPs()
for ip in ips:
    cidr = convert2cidr(ip[0], ip[1])
    answers = sendArp(cidr)
    state.append((cidr, answers))

print "\n\n--------------------8<--------------------\n\n"
for cidr, answers in state:
    if answers:
        print "    Promiscuous hosts on %s:" % cidr
        for packet in answers:
            print "        [*]  %s" % packet[0].getfieldval('pdst')
print "\n"

# end scapy
sys.exit(0)
