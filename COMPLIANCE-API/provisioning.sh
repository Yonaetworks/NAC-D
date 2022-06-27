apt update
apt install -y git
python2 get-pip.py
pip2 install requests ipaddress
git clone https://github.com/Yonaetworks/NAC-D/tree/main/SDN-CTRL pox
pox/pox.py forwarding.nacd samples.pretty_log log.level --DEBUG