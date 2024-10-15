#! /bin/bash
/sbin/ip6tables -A INPUT -p icmpv6 -j DROP
exec > /dev/null 2>&1

ip netns del h1
ip netns del h2
ip netns del h3

sleep 1

ip netns add h1
ip netns add h2
ip netns add h3

ip link set dtap0 netns h1
ip link set dtap1 netns h2
ip link set dtap2 netns h3


sysctl -w net.ipv6.conf.all.disable_ipv6=1 --quiet
ip netns exec h1 sysctl -w net.ipv6.conf.all.disable_ipv6=1 --quiet
ip netns exec h2 sysctl -w net.ipv6.conf.all.disable_ipv6=1 --quiet
ip netns exec h3 sysctl -w net.ipv6.conf.all.disable_ipv6=1 --quiet

h1='ip netns exec h1'
h2='ip netns exec h2'
h3='ip netns exec h3'

$h1 ip link set dev dtap0 up
$h2 ip link set dev dtap1 up
$h3 ip link set dev dtap2 up

$h1 ifconfig dtap0 192.168.10.1/24
$h2 ifconfig dtap1 192.168.20.1/24
$h3 ifconfig dtap2 192.168.30.1/24

$h1 route add default gw 192.168.10.5
$h2 route add default gw 192.168.20.5
$h3 route add default gw 192.168.30.5

$h1 arp -s 192.168.10.5 00:00:00:00:00:10
$h2 arp -s 192.168.20.5 00:00:00:00:00:10
$h3 arp -s 192.168.30.5 00:00:00:00:00:10