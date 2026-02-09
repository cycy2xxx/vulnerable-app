Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "vulnerable-app"

  config.vm.network "private_network", ip: "192.168.56.10"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
    vb.cpus = 1
    vb.name = "vulnerable-app"
  end

  config.vm.provision "shell", inline: <<-SHELL
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker vagrant
  SHELL
end
