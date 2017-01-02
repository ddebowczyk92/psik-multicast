#!/usr/bin/env python

import random
import argparse
import schedule
import time

from scapy.all import sendp
from scapy.layers.l2 import Ether

from lldp import Chassis_ID, Port_ID, TTL, EndOfPDU


def rand_mac():
    mac = [0x30, 0x85, 0xa9,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    result = []
    port_id = map(lambda y: "%02x" % y, mac)
    port_id = ":".join(port_id)

    mac[5] = 0x00
    chid = map(lambda y: "%02x" % y, mac)
    chid = ":".join(chid)

    result.append(chid)
    result.append(port_id)
    return result


def create_simple_lldp_packet(mac_addr):
    chassis_id = Chassis_ID()
    chassis_id.subtype = 0x07
    chassis_id.length = 22
    chassis_id.locallyAssigned = 'dpid:0000000000000008'
    # chassis_id.macaddr = mac_addr
    port_id = Port_ID()
    port_id.subtype = 0x02
    port_id.length = 5
    # port_id.length = 5
    #port_id.macaddr = mac_addr
    ttl = TTL()
    end = EndOfPDU()

    frame = Ether()
    frame.src = mac_addr
    frame.dst = '01:80:c2:00:00:0e'
    frame.type = 0x88cc

    packet = frame / chassis_id / port_id / ttl / end
    return packet


def send_packet(packet, interface):
    sendp(packet, verbose=1, iface=interface)


def main():
    parser = argparse.ArgumentParser(prog='LLDP GENERATOR')
    parser.add_argument('iface', help='iface help')
    parser.add_argument('macaddr', help='macaddr help')
    args = parser.parse_args()
    packet = create_simple_lldp_packet(args.macaddr)

    def callback():
        send_packet(packet, args.iface)

    schedule.every(1).second.do(callback)

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()
