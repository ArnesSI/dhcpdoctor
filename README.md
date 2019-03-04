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

## Icinga2 check command

You can use dhcpdoctor as a check command from Icinga2 or Nagios.

There is [dhcpdoctor.conf](dhcpdoctor.conf) config with a CheckCommand definition
for Icinga2 you can use. A service that uses this check command might look like
this:

```
apply Service "dhcpd6" {
    import "generic-service"
    check_command = "dhcpdoctor"
    vars.dhcpdoctor_ipv6 = true
    vars.dhcpdoctor_client_id = "00:11:11:11:11:11"
    assign where host.vars.dhcpd6
}
```

If you are building an RPM from provided [SPEC](dhcpdoctor.spec) file, the
CheckCommand config will be installed to
`/etc/icinga2/conf.d/check_commands/dhcpdoctor.conf`.

## Developing

We use [poetry](https://poetry.eustace.io/) to manage Python dependencies and virtual environments.

To setup development virtual environment:

```
poetry install
```

Run the tool:

```
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

## Releases

```
poetry run bumpversion patch
```

Instead of patch you can give `minor` or `major`.
This creates a commit and tag. Make sure to push it with `git push --tags`.

The `dev-version.sh` script will bump the version for development or release as
needed (based on whether we are on a git tag or not) and is called in CI jobs.

To publish a release to pypi.org run:

```
poetry build
poetry publish
```

## Building

Here is how to build `dhcpdoctor` using pyinstaller into a single binary file
and then package that into a RPM for Red-Hat based systems. The resulting
binary is setuid root, because `dhcpdoctor` needs to work on privileged UDP
ports, but is usually run as a special user when invoked from Nagios or Icinga.

```
pip3 install --upgrade bumpversion poetry pyinstaller
poetry install --no-dev
poetry run pip freeze | grep -v egg=dhcpdoctor > requirements.txt
pip3 install -r requirements.txt
./dev-version.sh
./build.sh
```
