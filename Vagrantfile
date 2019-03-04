#
# Vagrant environment with 3 machines:
#  * dhcpd4 - ISC dhcp ipv4 server
#  * dhcpd6 - ISC dhcp ipv6 server
#  * dhcpdoctor - runs dhcpdoctor against eny of the servers
#
# All three are connected to a caommon private network
# IP provisioning is done mostly via shell provisioner, because
# built-in vagrant options are too limited.
# dhcpdoctor has an extra IPv4 and IPv6 subnet so it can sumulate
# running as DHCP relay and still receive replies.
#
# Included centos boxes don't have virtualbox tools installed, so the
# working directory can't be mounted and is instead rsync-ed to VMs.
# To keep the code up to date while developing you sould run rsync-auto
# in a separate shell:
#
#     vagrant rsync-auto
#
Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |v|
    v.gui = false
  end

  config.vm.define "dhcpd4" do |dhcpd4|
    dhcpd4.vm.hostname = "dhcpd4"
    dhcpd4.vm.box = "centos/7"
    dhcpd4.vm.network "private_network", ip: "10.2.3.4", virtualbox__intnet: "dhcpdrnet"
    dhcpd4.vm.provision "shell", inline: <<-SHELL
      sudo ip addr add 10.2.3.4/24 dev eth1
      sudo ip route add 10.2.30.0/24 dev eth1
      sudo yum install -y dhcp tcpdump
      sudo cp -v /vagrant/tests/dhcpd/dhcpd.conf /etc/dhcp/dhcpd.conf
      sudo systemctl start dhcpd
    SHELL
  end

  config.vm.define "dhcpd6" do |dhcpd6|
    dhcpd6.vm.hostname = "dhcpd6"
    dhcpd6.vm.box = "centos/7"
    dhcpd6.vm.network "private_network", ip: "10.2.3.6", virtualbox__intnet: "dhcpdrnet"
    dhcpd6.vm.provision "shell", inline: <<-SHELL
      sudo ip addr add fc00:3::6/64 dev eth1
      sudo ip route add fc00:30::5/64 dev eth1
      sudo yum install -y dhcp tcpdump
      sudo cp -v /vagrant/tests/dhcpd/dhcpd6.conf /etc/dhcp/dhcpd6.conf
      sudo ip link set eth1 promisc on
      sudo systemctl start dhcpd6
    SHELL
    # uncomment to have virtualbox capture packets before they reach the VM
    #dhcpd6.vm.provider "virtualbox" do |v|
    #  v.customize ["modifyvm", :id, "--nictrace2", "on"]
    #  v.customize ["modifyvm", :id, "--nictracefile2", "dhcp.pcap"]
    #end
  end

  config.vm.define "dhcpdoctor" do |dhcpdoctor|
    dhcpdoctor.vm.hostname = "dhcpdoctor"
    dhcpdoctor.vm.box = "centos/7"
    dhcpdoctor.vm.network "private_network", ip: "10.2.3.5", virtualbox__intnet: "dhcpdrnet"
    dhcpdoctor.vm.provision "shell", inline: <<-SHELL
      sudo ip addr add 10.2.3.5/24 dev eth1
      sudo ip addr add fc00:3::5/64 dev eth1
      sudo ip addr add 10.2.30.5/24 dev eth1
      sudo ip addr add fc00:30::5/64 dev eth1
      sudo yum install -y epel-release
      sudo yum install -y git-core python36-pip which tcpdump
      sudo /usr/bin/pip3.6 install --upgrade pip
      sudo /usr/local/bin/pip3.6 install poetry
      cd /vagrant/
      sudo /usr/local/bin/poetry install
    SHELL
  end

end
