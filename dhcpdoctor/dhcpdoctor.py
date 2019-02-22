import argparse
import binascii
import sys
import threading

import scapy
from scapy.all import (
    BOOTP,
    DHCP,
    IP,
    UDP,
    AnsweringMachine,
    Ether,
    conf,
    get_if_addr,
    get_if_hwaddr,
    get_if_raw_hwaddr,
    send,
    sendp,
    sniff,
)

from dhcpdoctor import settings

__version__ = '0.1.0'


def mac_str_to_bytes(mac):
    """Converts string representation of a MAC address to bytes
    
    Args:
        mac (str): String representation of a MAC address. Can contain
            colones, dots and dashes which will be stripped.
    
    Raises:
        TypeError: if a given mac is not a sting

    Returns:
        (bytes): MAC address in bytes form
    """
    if isinstance(mac, bytes):
        return mac
    if not isinstance(mac, str):
        raise TypeError('MAC address given must be a string')
    mac = mac.replace(':', '').replace('-', '').replace('.', '')
    return binascii.unhexlify(mac)


def sniffer(dhcp_client):
    """Starts scapy sniffer and stops when a timeout is reached or a valid packet
        is received.
    
    Args:
        dhcp_client (DHCPClient): Instance of DHCPClient class that implements
            `is_matching_reply` method
    """

    def show_packet(x):
        if settings.DEBUG:
            x.summary()

    sniff(
        prn=show_packet,
        timeout=settings.TIMEOUT,
        stop_filter=dhcp_client.is_matching_reply,
    )


class DHCPv4:
    def __init__(self):
        self.xid = 1
        self.request = None
        self.reply = None
        self.sniffer = None

    def craft_request(self, *args, **kwargs):
        self.request = self.craft_discover(*args, **kwargs)
        if settings.RELAY_MODE:
            self.add_relay(
                self.request, settings.SERVER_ADDRESS, settings.RELAY_ADDRESS
            )
        return self.request

    def craft_discover(self, hw=None):
        """Generates a DHCPDICSOVER packet
        
        Args:
            hw (str|bytes, optional): Defaults to None. Client MAC address to place
                in `chaddr`.
        
        Returns:
            scapy.layers.inet.IP: DHCPDISCOVER packet
        """

        if not hw:
            _, hw = get_if_raw_hwaddr(conf.iface)
        else:
            hw = mac_str_to_bytes(hw)
        dhcp_discover = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=hw, xid=self.xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        # TODO: param req list
        return dhcp_discover

    def add_relay(self, p, srv_ip, relay_ip=None):
        """Modify passed DHCP cient packet as if a DHCP relay would
        
        Add giaddr, update UDP src port and set IP dest address.
        
        Args:
            p (scapy.packet.Packet): DHCP client packet
            srv_ip (str): IP address of server to relay to
            relay_ip (str, optional): Defaults to dhcpdoctor's IP. IP address of relay.
        """

        if not relay_ip:
            relay_ip = get_if_addr(conf.iface)
        p[BOOTP].giaddr = relay_ip
        p[BOOTP].flags = 0  # unset broadcast flag
        p[UDP].sport = 67
        p[IP].src = relay_ip
        p[IP].dst = srv_ip

    def send(self):
        if settings.RELAY_MODE:
            # sending unicast, let scapy handle ethernet
            send(self.request, verbose=settings.DEBUG)
        else:
            # sending broadcast, need to set Ethernet ourselves
            sendp(Ether(dst="FF:FF:FF:FF:FF:FF") / self.request, verbose=settings.DEBUG)

    def sniff_start(self):
        """Starts listening for packets in a new thread"""
        self.sniffer = threading.Thread(target=sniffer, args=[self])
        self.sniffer.start()

    def sniff_stop(self):
        """Waits for sniffer thread to finish"""
        self.sniffer.join()

    def is_matching_reply(self, reply):
        """Check that received packet is a response to a request sent by this instance

        A bootp transaction ID must match.
        
        Args:
            reply (scapy.packet.Packet): Packet received by sniffer
        
        Returns:
            bool: True if packet matches
        """
        if (
            reply.haslayer(BOOTP)
            and reply[BOOTP].op == 2
            and reply[BOOTP].xid == self.xid
            and reply.haslayer(DHCP)
            and self.is_offer_type(reply)
        ):
            self.reply = reply
            return True
        return False

    def is_offer_type(self, packet):
        """Checks that packet contains DHCP message-type that offers an  address
        
        Packet must be a DHCPOFFER (2)
        
        Args:
            reply (scapy.packet.Packet): Packet to check
        
        Returns:
            bool: True if packet matches
        """
        if not packet.haslayer(DHCP):
            return False
        req_type = [x[1] for x in packet[DHCP].options if x[0] == 'message-type'][0]
        if req_type in [2]:
            return True
        return False


def run_test():
    """Runs test and exits with appropriate exit code"""

    # configure default scapy interface
    conf.iface = settings.IFACE or conf.iface

    dhcp_client = DHCPv4()
    p = dhcp_client.craft_request()

    dhcp_client.sniff_start()
    dhcp_client.send()
    dhcp_client.sniff_stop()

    r = dhcp_client.reply

    if r:
        print('got reply!')
        sys.exit(0)
    else:
        print('NO REPLY FOUND!!!')
        sys.exit(2)


def parse_cmd_args():
    """Parse command line arguments

    Sets settings accordingly.
    """
    parser = argparse.ArgumentParser(
        description='Tool for testing IPv4 and IPv6 DHCP services'
    )
    parser.add_argument(
        '-V', '--version', action='version', version='%(prog)s {}'.format(__version__)
    )
    parser.add_argument('-d', dest='debug', action='store_true', help='debugging mode')
    parser.add_argument(
        '-i',
        '--interface',
        dest='iface',
        type=str,
        required=False,
        help='interface to send requests via',
    )
    parser.add_argument(
        '-r',
        '--relay',
        dest='relay_dst',
        type=str,
        required=False,
        help='send requests to specified server instead of broadcasting them on the local network',
    )
    parser.add_argument(
        '-f',
        '--relay-from',
        dest='relay_src',
        type=str,
        required=False,
        help='send relayed requests from specified address. Defaults to address of the interface requests are sent from.',
    )
    parser.add_argument(
        '--timeput',
        dest='timeout',
        type=int,
        required=False,
        help='Time to wait for response from server before giving up.',
        default=settings.TIMEOUT,
    )
    args = parser.parse_args()
    settings.DEBUG = args.debug
    settings.IFACE = args.iface
    settings.TIMEOUT = args.timeout
    if args.relay_dst:
        settings.RELAY_MODE = True
        settings.SERVER_ADDRESS = args.relay_dst
        if args.relay_src:
            settings.RELAY_ADDRESS = args.relay_from


def main():
    parse_cmd_args()
    run_test()


if __name__ == "__main__":
    main()
