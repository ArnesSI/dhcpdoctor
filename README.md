# dhcpdoctor

Tool for testing IPv4 and IPv6 DHCP services

![Logo](logo.png)

## Description

dhcpdoctor sends DHCP requests and checks if it gets an offer from DHCP server.
It supports BOOTP+DHCP for IPv4 (`-4`) and DHCPv6 for IPv6 (`-6`).

It can operate as a DHCP client by sending requests on the local network via
broadcast/multicast or as a DHCP client and relay in one tool by unicasting
requests to the specified IP address (`-s`). When relaying requests you can
specify the relay address to send from (`-f`). By default the IP address of
the interface request is sent from is used. When specifying custom relay from
address, keep in mind that the DHCP server will send the response back to the
address you specify here, so it must be an address on the machine you are
running tests from.

You can specify a custom client MAC or DUID (`-c`). By default the MAC address
of the interface to send request from is used.

You can specify the interface to send requests from with `-i`.

Program output and exit codes are Nagios/Icinga [compatible](https://nagios-plugins.org/doc/guidelines.html). Response time from DHCP server is measured and returned as performance data.

## Requirements

dhcpdoctor needs needs Python 3.4 or later to run.

Since it uses [scapy](https://scapy.net/) under the hood to craft, dissect, send and receive packets, it needs root permissions to run.

## Installing

Via pip:

```
pip install dhcpdoctor
```

## Developing

We use [poetry](https://poetry.eustace.io/) to manage Python dependencies and virtual environments:

```
poetry install
poetry run dhcpdoctor -h
```

[Vagrant](https://www.vagrantup.com/) can be used to quickly spin-up VMs with 
DHCP servers to test against:

```
vagrant up
vagrant ssh dhcpdoctor
cd /vagrant
poetry run dhcpdoctor -h
exit
vagrant destroy
```

See comments in [Vagrantfile](Vagrantfile) for more information.
