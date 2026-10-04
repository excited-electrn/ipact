#!/usr/bin/env bash
set -euo pipefail

# Create a persistent TUN device owned by user, so program needs no root
sudo ip tuntap add dev tun0 mode tun user "$USER"
sudo ip addr add 10.0.0.1/24 dev tun0 # kernel end
sudo ip link set tun0 up

ip addr show tun0
ip route | grep tun0

# remove 
# sudo ip tuntap del dev tun0 mode tun
