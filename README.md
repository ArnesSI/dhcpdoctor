# dhcpdoctor

Tool for testing IPv4 and IPv6 DHCP services

## Description

dhcpdoctor sends DHCP requests and checks if it gets an offer from DHCP server.
It supports BOOTP+DHCP for IPv4 (`-4`) and DHCPv6 for IPv6 (`-6`).

It can operate as a DHCP client by sending requests on the local network via
broadcast/multicast or as a DHCP clent and relay in one tool by unicasting
requests to the specified IP address (`-s`). When relaying requests you can
specify the relay address to send from (`-f`). By default the IP address of
the interface request is sent from is used. When specifying custom relay from
address, keep in mind that the DHCP server will send the response back to the
address you specify here, so it must be an address on the machine you are
running tests from.

You can specify a custom client MAC or DUID (`-c`). By default the MAC address
of the interface to send request from is used.

You can specify the interface to send requests from with `-i`.

