import argparse
import binascii
import sys
import threading
from random import randint

from scapy.all import (
    BOOTP,
    DHCP,
    DHCP6,
    DUID_LL,
    IP,
    UDP,
    AnsweringMachine,
    DHCP6_Advertise,
    DHCP6_RelayForward,
    DHCP6_Reply,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptElapsedTime,
    DHCP6OptIA_NA,
    DHCP6OptIAAddress,
    DHCP6OptRelayMsg,
    Ether,
    IPv6,
    conf,
    get_if_addr,
    get_if_addr6,
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


class DHCPClient:
    def __init__(self):
        self.xid = randint(0, (2 ** 24) - 1)  # BOOTP 4 bytes, DHCPv6 3 bytes
        self.request = None
        self.reply = None
        self.sniffer = None
        self.offered_address = None

    def craft_request(self, *args, **kwargs):
        self.request = self.craft_discover(*args, **kwargs)
        if settings.RELAY_MODE:
            self.add_relay(
                self.request, settings.SERVER_ADDRESS, settings.RELAY_ADDRESS
            )
        if settings.DEBUG:
            print(self.request.show())
        return self.request

    def craft_discover(self, hw=None):
        raise NotImplementedError

    def add_relay(self, p, srv_ip, relay_ip=None):
        raise NotImplementedError

    def send(self):
        if settings.RELAY_MODE:
            # sending unicast, let scapy handle ethernet
            send(self.request, verbose=settings.DEBUG)
        else:
            # sending to local link, need to set Ethernet ourselves
            sendp(
                Ether(dst=self._get_ether_dst()) / self.request, verbose=settings.DEBUG
            )

    def sniff_start(self):
        """Starts listening for packets in a new thread"""
        self.sniffer = threading.Thread(target=sniffer, args=[self])
        self.sniffer.start()

    def sniff_stop(self):
        """Waits for sniffer thread to finish"""
        self.sniffer.join()

    def is_matching_reply(self, reply):
        """Checks that we got reply packet

        Called for each packet captured by sniffer.
        
        Args:
            reply (scapy.packet.Packet): Packet received by sniffer
        
        Returns:
            bool: True if packet matches
        """
        if self.is_offer_type(reply):
            self.reply = reply
            if settings.DEBUG:
                print(reply.show())
            self.offered_address = self.get_offered_address()
            return True
        return False

    def is_offer_type(self, packet):
        raise NotImplementedError

    def get_offered_address(self):
        raise NotImplementedError

    def _get_ether_dst(self):
        raise NotImplementedError


class DHCPv4Client(DHCPClient):
    MAC_BROADCAST = 'FF:FF:FF:FF:FF:FF'

    def craft_discover(self, hw=None):
        """Generates a DHCPDICSOVER packet
        
        Args:
            hw (str|bytes, optional): Defaults to MAC of Scapy's `conf.iface`.
                Client MAC address to place in `chaddr`.
        
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
        if settings.DEBUG:
            print(dhcp_discover.show())
        return dhcp_discover

    def add_relay(self, p, srv_ip, relay_ip=None):
        """Modify passed DHCP client packet as if a DHCP relay would
        
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
        if settings.DEBUG:
            print(p.show())

    def is_offer_type(self, packet):
        """Checks that packet is a valid DHCP reply
        
        The following are checked:
        * packet contains BOOTP and DHCP layers
        * BOOTP xid matches request
        * DHCP message-type must be a DHCPOFFER (2) (others can be added later)
        
        Args:
            reply (scapy.packet.Packet): Packet to check
        
        Returns:
            bool: True if packet matches
        """
        if not packet.haslayer(BOOTP):
            return False
        if packet[BOOTP].op != 2:
            return False
        if packet[BOOTP].xid != self.xid:
            return False
        if not packet.haslayer(DHCP):
            return False
        req_type = [x[1] for x in packet[DHCP].options if x[0] == 'message-type'][0]
        if req_type in [2]:
            return True
        return False

    def get_offered_address(self):
        return self.reply[BOOTP].yiaddr

    def _get_ether_dst(self):
        return self.MAC_BROADCAST


class DHCPv6Client(DHCPClient):
    MAC_MCAST = '33:33:00:00:00:02'

    def craft_discover(self, hw=None):
        """Generates a DHCPv6 Solicit packet
        
        Args:
            hw (str|bytes, optional): Defaults to MAC of Scapy's `conf.iface`.
                Client MAC address to use for DUID LL.
        
        Returns:
            scapy.layers.inet.IPv6: DHCPv6 Solicit packet
        """
        if not hw:
            _, hw = get_if_raw_hwaddr(conf.iface)
        else:
            hw = mac_str_to_bytes(hw)

        dhcp_solicit = (
            IPv6(dst="ff02::1:2")
            / UDP(sport=546, dport=547)
            / DHCP6_Solicit(trid=self.xid)
            / DHCP6OptElapsedTime()
            / DHCP6OptClientId(duid=DUID_LL(lladdr=hw))
            / DHCP6OptIA_NA(iaid=0)
        )
        if settings.DEBUG:
            print(dhcp_solicit.show())
        return dhcp_solicit

    def add_relay(self, p, srv_ip, relay_ip=None):
        """Modify passed DHCP client packet as if a DHCP relay would
        
        Encapsulate DHCPv6 request message into DHCPv6 RelayForward, update UDP
            src port and set IP dest address.
        
        Args:
            p (scapy.packet.Packet): DHCP client packet
            srv_ip (str): IPv6 address of server to relay to
            relay_ip (str, optional): Defaults to dhcpdoctor's IPv6. IPv6 address
                of relay.
        """
        if not relay_ip:
            relay_ip = get_if_addr6(conf.iface)

        # get payload of UDP to get whatever type of DHCPv6 request it is and
        # replace it with our relay data
        dhcp_request = p[UDP].payload
        assert isinstance(dhcp_request, DHCP6)
        p[UDP].remove_payload()
        p[UDP].add_payload(
            DHCP6_RelayForward(linkaddr=relay_ip, peeraddr=p[IPv6].src)
            / DHCP6OptRelayMsg(message=dhcp_request)
        )

        p[UDP].sport = 547
        p[IPv6].src = relay_ip
        p[IPv6].dst = srv_ip
        if settings.DEBUG:
            print(p.show())

    def is_offer_type(self, packet):
        """Checks that a packet is a valid DHCPv6 reply
        
        The following are checked:
        * packet contains DHCPv6 Advertise or Reply
        * Transaction ID matches request
        * packet contains IA_NA option
        
        Args:
            packet (scapy.packet.Packet): Packet to check
        
        Returns:
            bool: True if packet matches
        """

        if not (packet.haslayer(DHCP6_Advertise) or packet.haslayer(DHCP6_Reply)):
            return False
        if packet[DHCP6_Advertise].trid != self.xid:
            return False
        if not packet.haslayer(DHCP6OptIA_NA):
            return False
        return True

    def get_offered_address(self):
        return self.reply[DHCP6OptIAAddress].addr

    def _get_ether_dst(self):
        return self.MAC_MCAST


def run_test():
    """Runs test and exits with appropriate exit code"""

    # configure default scapy interface
    conf.iface = settings.IFACE or conf.iface

    if settings.PROTOCOL == 4:
        dhcp_client = DHCPv4Client()
    elif settings.PROTOCOL == 6:
        dhcp_client = DHCPv6Client()

    dhcp_client.craft_request(hw=settings.CLIENT_ID)
    dhcp_client.sniff_start()
    dhcp_client.send()
    dhcp_client.sniff_stop()

    if dhcp_client.reply:
        print('got reply with address {}'.format(dhcp_client.offered_address))
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
    parser.add_argument('-d', dest='DEBUG', action='store_true', help='debugging mode')
    proto_group = parser.add_mutually_exclusive_group()
    proto_group.add_argument(
        '-4', dest='PROTOCOL', action='store_const', const=4, help='IPv4 mode'
    )
    proto_group.add_argument(
        '-6', dest='PROTOCOL', action='store_const', const=6, help='IPv6 mode'
    )
    parser.add_argument(
        '-i',
        '--interface',
        dest='IFACE',
        type=str,
        required=False,
        help='interface to send requests via',
    )
    parser.add_argument(
        '-c',
        '--client-id',
        dest='CLIENT_ID',
        type=str,
        required=False,
        help='MAC address or DUID of client to send in request. Defaults to MAC address of interface requests are sent from.',
    )
    parser.add_argument(
        '-r',
        '--relay',
        dest='SERVER_ADDRESS',
        type=str,
        required=False,
        help='send requests to specified server instead of broadcasting them on the local network',
    )
    parser.add_argument(
        '-f',
        '--relay-from',
        dest='RELAY_ADDRESS',
        type=str,
        required=False,
        help='send relayed requests from specified address. Defaults to address of the interface requests are sent from.',
    )
    parser.add_argument(
        '--timeout',
        dest='TIMEOUT',
        type=int,
        required=False,
        help='Time to wait for response from server before giving up.',
    )
    parser.set_defaults(
        PROTOCOL=settings.PROTOCOL,
        TIMEOUT=settings.TIMEOUT,
        CLIENT_ID=settings.CLIENT_ID,
    )
    args = parser.parse_args()
    # argument validation
    if args.RELAY_ADDRESS and not args.SERVER_ADDRESS:
        parser.error('The --relay-from [-f] argument can only be used with --relay [-r] argument.')
    settings.DEBUG = args.DEBUG
    settings.IFACE = args.IFACE
    settings.CLIENT_ID = args.CLIENT_ID
    settings.TIMEOUT = args.TIMEOUT
    settings.PROTOCOL = args.PROTOCOL
    if args.SERVER_ADDRESS:
        settings.RELAY_MODE = True
        settings.SERVER_ADDRESS = args.SERVER_ADDRESS
        if args.RELAY_ADDRESS:
            settings.RELAY_ADDRESS = args.RELAY_ADDRESS


def main():
    parse_cmd_args()
    run_test()


if __name__ == "__main__":
    main()
