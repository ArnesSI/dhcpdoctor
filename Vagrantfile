Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |v|
    v.gui = false
  end

  config.vm.define "dhcpd4" do |dhcpd4|
    dhcpd4.vm.box = "centos/7"
    dhcpd4.vm.network "private_network", ip: "10.2.3.13"
    dhcpd4.vm.provision "shell", inline: <<-SHELL
      sudo yum install -y dhcp tcpdump
      sudo cp -v /vagrant/docker/dhcpd/dhcpd.conf /etc/dhcp/dhcpd.conf
      sudo systemctl start dhcpd
    SHELL
  end

  config.vm.define "dhcpdoctor" do |dhcpdoctor|
    dhcpdoctor.vm.box = "centos/7"
    dhcpdoctor.vm.network "private_network", ip: "10.2.3.5"
    dhcpdoctor.vm.provision "shell", inline: <<-SHELL
      sudo yum install -y epel-release
      sudo yum install -y git-core python36-pip which tcpdump
      sudo /usr/bin/pip3.6 install --upgrade pip
      sudo /usr/local/bin/pip3.6 install poetry
      cd /vagrant/
      sudo /usr/local/bin/poetry install
    SHELL
  end

end
