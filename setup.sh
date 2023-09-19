sudo ip link add name fabric type bridge
sudo ip link set dev fabric up

host=host1
ip=192.168.0.1/24
sudo ip netns add ${host}
sudo ip link add name ${host}-phy type veth peer name ${host}-fab
sudo ip link set dev ${host}-fab up
sudo ip link set dev ${host}-fab master fabric
sudo ip link set dev ${host}-phy netns ${host}
sudo ip netns exec ${host} ip link set dev ${host}-phy up
sudo ip netns exec ${host} ip addr add ${ip} dev ${host}-phy


ns=ns1
ip=10.0.0.1/24
table=1
sudo ip netns add ${ns}
sudo ip link add name ${ns} type veth peer name ${host}-${ns}
sudo ip link set ${ns} netns ${ns}
sudo ip link set ${host}-${ns} netns ${host}
sudo ip netns exec ${host} ip link set ${host}-${ns} up
sudo ip netns exec ${ns} ip link set ${ns} up
sudo ip netns exec ${ns} ip addr add ${ip} dev ${ns}
sudo ip netns exec ${host} ip link add ${ns}-vrf type vrf table ${table}
sudo ip netns exec ${host} ip link set ${ns}-vrf up
sudo ip netns exec ${host} ip link set ${host}-${ns} master ${ns}-vrf

#sudo ip netns exec ${ns} ip route change 10.0.0.0/24 dev ns1 proto kernel scope link src ${ip} advmss 2900


host=host2
ip=192.168.0.2/24
sudo ip netns add ${host}
sudo ip link add name ${host}-phy type veth peer name ${host}-fab
sudo ip link set dev ${host}-fab up
sudo ip link set dev ${host}-fab master fabric
sudo ip link set dev ${host}-phy netns ${host}
sudo ip netns exec ${host} ip link set dev ${host}-phy up
sudo ip netns exec ${host} ip addr add ${ip} dev ${host}-phy


ns=ns2
ip=10.0.0.2/24
table=2
sudo ip netns add ${ns}
sudo ip link add name ${ns} type veth peer name ${host}-${ns}
sudo ip link set ${ns} netns ${ns}
sudo ip link set ${host}-${ns} netns ${host}
sudo ip netns exec ${host} ip link set ${host}-${ns} up
sudo ip netns exec ${ns} ip link set ${ns} up
sudo ip netns exec ${ns} ip addr add ${ip} dev ${ns}
sudo ip netns exec ${host} ip link add ${ns}-vrf type vrf table ${table}
sudo ip netns exec ${host} ip link set ${ns}-vrf up
sudo ip netns exec ${host} ip link set ${host}-${ns} master ${ns}-vrf


sudo ip netns del ns1 
sudo ip netns del ns2
sudo ip link del host1
sudo ip link del host2
sudo ip link del host1-phy
sudo ip link del host2-phy
sudo ip link del fabric


bpftrace -e \
'tracepoint:xdp:xdp_redirect*_err {@redir_errno[-args->err] = count();}
tracepoint:xdp:xdp_devmap_xmit {@devmap_errno[-args->err] = count();}'

bpftrace -e 'tracepoint:xdp:* { @cnt[probe] = count(); }'


ssh 192.168.105.6 "sudo ip netns exec r1 tcpdump -U -nni r1_link2 -w -" | wireshark -k -i -