%global srcname dhcpdoctor
%define version _VERSION_
%define icingadest /etc/icinga2/conf.d/check_commands

Name: dhcpdoctor
Version: %{version}
Release: 1%{?dist}
Summary: Tool for testing IPv4 and IPv6 DHCP services
License: MIT
URL: https://github.com/ArnesSI/dhcpdoctor
Source0: dist/%{srcname}-%{version}.tar.gz
Source1: dhcpdoctor.conf

BuildRequires: python34-devel
BuildRequires: python34-pip

%description
dhcpdoctor sends DHCP requests and checks if it gets an offer from DHCP server.
It supports BOOTP+DHCP for IPv4 and DHCPv6 for IPv6.

It can operate as a DHCP client by sending requests on the local network via
broadcast/multicast or as a DHCP client and relay in one tool by unicasting
requests to the specified IP address.

%prep
%autosetup -n %{srcname}-%{version}

%build
pyinstaller --onefile dhcpdoctor/dhcpdoctor.py -n dhcpdoctor

%install
install -p -D -m 4755 dist/dhcpdoctor %{buildroot}%{_bindir}/dhcpdoctor
install -p -D -m 0644 %_sourcedir/dhcpdoctor.conf  %{buildroot}%{icingadest}/dhcpdoctor.conf

%files
%defattr(-,root,root,-)
%{_bindir}/dhcpdoctor
%{icingadest}/dhcpdoctor.conf
