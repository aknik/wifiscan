sudo airmon-ng stop mon0
sudo airmon-ng stop wlan0
sudo airmon-ng start wlan0
sudo killall avahi-daemon
sudo killall dhclient

sudo python wifiscan.py mon0

