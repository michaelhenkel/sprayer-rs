sudo apt install zsh gcc llvm-16-linker-tools libpolly-16-dev llvm-16 build-essential libz-dev pkg-config libssl-dev libelf-dev -y
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install --no-default-features bpf-linker
cargo install cargo-generate
cd /private/lima-build
git clone https://github.com/michaelhenkel/sprayer-rs


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


init_c1=$(ip -s l show dev r1_link1 |grep RX -A1|tail -1 |awk '{print $1}')
init_c2=$(ip -s l show dev r1_link2 |grep RX -A1|tail -1 |awk '{print $1}')
init_c3=$(ip -s l show dev r1_link3 |grep RX -A1|tail -1 |awk '{print $1}')
init_c4=$(ip -s l show dev r1_link4 |grep RX -A1|tail -1 |awk '{print $1}')
while true;
do
	c1=$(ip -s l show dev r1_link1 |grep RX -A1|tail -1 |awk '{print $1}')
	c2=$(ip -s l show dev r1_link2 |grep RX -A1|tail -1 |awk '{print $1}')
	c3=$(ip -s l show dev r1_link3 |grep RX -A1|tail -1 |awk '{print $1}')
	c4=$(ip -s l show dev r1_link4 |grep RX -A1|tail -1 |awk '{print $1}')
	echo r1_link1: $((${c1}-${init_c1}))
	echo r1_link2: $((${c2}-${init_c2}))
	echo r1_link3: $((${c3}-${init_c3}))
	echo r1_link4: $((${c4}-${init_c4}))
	sleep 1
	clear
done

tc qdisc add dev r2_link1 root netem delay 120ms
tc qdisc add dev r2_link2 root netem delay 130ms
tc qdisc add dev r2_link3 root netem delay 140ms


tc qdisc del dev r2_link1 root netem
tc qdisc del dev r2_link2 root netem
tc qdisc del dev r2_link3 root netem

tc qdisc add dev r1_link1 root netem delay 1ms
tc qdisc add dev r1_link2 root netem delay 2ms
tc qdisc add dev r1_link3 root netem delay 3ms


tc qdisc del dev r1_link1 root netem
tc qdisc del dev r1_link2 root netem
tc qdisc del dev r1_link3 root netem
