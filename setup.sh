sudo ip link add name fabric type bridge
sudo ip link set dev fabric up

host=host1
sudo ip link add name ${host} type bridge
sudo ip link set dev ${host} up
sudo ip link add name ${host}-phy type veth peer name ${host}-fab
sudo ip link set dev ${host}-fab up
sudo ip link set dev ${host}-phy up
sudo ip link set dev ${host}-fab master fabric
sudo ip link set dev ${host}-phy master ${host}
sudo ip link set dev ${host}-fab mtu 3000
sudo ip link set dev ${host}-phy mtu 3000

ns=ns1
ip=10.0.0.1/24
sudo ip netns add ${ns}
sudo ip link add name ${ns} type veth peer name ${host}-${ns}
sudo ip link set ${ns} netns ${ns}
sudo ip link set ${host}-${ns} up
sudo ip netns exec ${ns} ip link set ${ns} up
sudo ip netns exec ${ns} ip addr add ${ip} dev ${ns}
sudo ip link set dev ${host}-${ns} master ${host}
sudo ip netns exec ${ns} ip route change 10.0.0.0/24 dev ns1 proto kernel scope link src ${ip} advmss 2900


host=host2
sudo ip link add name ${host} type bridge
sudo ip link set dev ${host} up
sudo ip link add name ${host}-phy type veth peer name ${host}-fab
sudo ip link set dev ${host}-fab up
sudo ip link set dev ${host}-phy up
sudo ip link set dev ${host}-fab master fabric
sudo ip link set dev ${host}-phy master ${host}
sudo ip link set dev ${host}-fab mtu 3000
sudo ip link set dev ${host}-phy mtu 3000

ns=ns2
ip=10.0.0.2/24
sudo ip netns add ${ns}
sudo ip link add name ${ns} type veth peer name ${host}-${ns}
sudo ip link set ${ns} netns ${ns}
sudo ip link set ${host}-${ns} up
sudo ip netns exec ${ns} ip link set ${ns} up
sudo ip netns exec ${ns} ip addr add ${ip} dev ${ns}
sudo ip link set dev ${host}-${ns} master ${host}
sudo ip netns exec ${ns} ip route change 10.0.0.0/24 dev ns1 proto kernel scope link src ${ip} advmss 2900


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