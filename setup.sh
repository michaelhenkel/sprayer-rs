sudo ip link del dev ns1-veth0 || true
sudo ip link del dev ns2-veth0 || true
sudo ip netns del ns1 || true
sudo ip netns del ns2 || true
sudo ip link del br0 || true

sudo ip netns add ns1
sudo ip link add name ns1-veth0 type veth peer name ns1-veth1
sudo ip link set ns1-veth1 netns ns1
sudo ip link set ns1-veth0 up
sudo ip netns exec ns1 ip address add 10.0.0.1/24 dev ns1-veth1
sudo ip netns exec ns1 ip link set ns1-veth1 up

sudo ip netns add ns2
sudo ip link add name ns2-veth0 type veth peer name ns2-veth1
sudo ip link set ns2-veth1 netns ns2
sudo ip link set ns2-veth0 up
sudo ip netns exec ns2 ip address add 10.0.0.2/24 dev ns2-veth1
sudo ip netns exec ns2 ip link set ns2-veth1 up

sudo ip link add name br0 type bridge
sudo ip link set dev ns1-veth0 master br0
sudo ip link set dev ns2-veth0 master br0
sudo ip link set dev br0 up
