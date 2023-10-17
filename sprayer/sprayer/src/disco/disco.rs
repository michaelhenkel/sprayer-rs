use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use afxdp::buf::Buf;
use afxdp::buf_mmap::BufMmap;
use afxdp::mmap_area::{MmapAreaOptions, MmapArea};
use anyhow::anyhow;
use aya::Bpf;
use aya::maps::{Map, HashMap};
use network_types::eth::EthHdr;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::arp::MutableArpPacket;
use pnet::util::MacAddr;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::MutablePacket;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations};
use std::collections::HashMap as ColHashMap;

use tonic::{transport::Server, Request, Response, Status};

use super::server::get_server::{Get, GetServer};
use super::server::{StatsRequest, StatsReply};

pub mod server {
    tonic::include_proto!("server"); // The string specified here must match the proto package name
}


use crate::buffer::buffer::{State, StateType, BufCustom, SocketType};


const BUFF_SIZE: usize = 2048;
const BUF_NUM: usize = 65535;
const BATCH_SIZE: usize = 32;

#[derive(Debug)]
pub struct MyServer {
    tx: tokio::sync::mpsc::Sender<StatsMsg>,
}

#[tonic::async_trait]
impl Get for MyServer {
    async fn get_stats(
        &self,
        request: Request<StatsRequest>,
    ) -> Result<Response<StatsReply>, Status> {
        println!("Got a request: {:?}", request);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let stats_msg = StatsMsg{
            msg: "".to_string(),
            tx,
        };
        self.tx.send(stats_msg).await.unwrap();

        let repl = rx.await.unwrap();
        // request.into_inner().name

        let reply = StatsReply {
            message: format!("stats {}!", repl).into(), // We must use .into_inner() as the fields of gRPC requests and responses are private
        };

        Ok(Response::new(reply)) // Send back our formatted greeting
    }
}

pub struct StatsMgr{
    xdp_load_balance_bpf: Bpf,
    rx: tokio::sync::mpsc::Receiver<StatsMsg>,
}

pub struct StatsMsg{
    msg: String,
    tx: tokio::sync::oneshot::Sender<u32>
}

impl StatsMgr {
    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            while let Some(msg) = self.rx.recv().await {
                let stats_map = self.xdp_load_balance_bpf.map_mut("STATSMAP").unwrap();
                let stats_map: HashMap<_, u32, u32> = HashMap::try_from(stats_map)?;
                let stats = stats_map.get(&0, 0).unwrap();
                msg.tx.send(stats).unwrap();
                
                println!("Got a message: {}", msg.msg);
            }
        }
    }
}

pub struct PeerDisco{
    interfaces: Vec<String>,
    interval: u64,
    peer_map_fd: i32,
}

impl PeerDisco {
    pub fn new(interfaces: Vec<String>, interval: u64, peer_map_fd: i32) -> Self {
        PeerDisco{
            interfaces,
            interval,
            peer_map_fd,
        }
    }
    pub async fn run(&mut self, xdp_load_balance_bpf: Bpf) -> anyhow::Result<()>{
        
        let (tx, rx) = tokio::sync::mpsc::channel(100);


        let stats_jh = tokio::spawn(async move{
            let mut stats_mgr = StatsMgr{
                xdp_load_balance_bpf,
                rx,
            };
            stats_mgr.run().await.unwrap();
        });


        let server_jh = tokio::spawn(async move{
            let addr = "[::1]:50051".parse().unwrap();
            let my_server = MyServer{tx};
        
            Server::builder()
                .add_service(GetServer::new(my_server))
                .serve(addr)
                .await.unwrap();
        });

        futures::future::join(stats_jh, server_jh).await;
        /*
        let interfaces = self.interfaces.clone();
        let jh = tokio::spawn(
            send_arp(interfaces, self.interval)
        );
        let mut wait = vec![
            jh,
        ];
        let mut peer_map_fd = self.peer_map_fd.clone();
        let interfaces = self.interfaces.clone();
        let bpf = Arc::new(Mutex::new(xdp_load_balance_bpf));
        for intf in &interfaces{
            peer_map_fd = peer_map_fd.clone();
            let jh = tokio::spawn(
                recv_arp(intf.clone(), peer_map_fd, bpf.clone())
            );
            wait.push(jh);

        }
        for t in wait {
            t.await.expect("server failed").unwrap();
        }
        */
        Ok(())

    }


}

pub async fn recv_arp(interface: String, peer_map_fd: i32, bpf: Arc<Mutex<Bpf>> ) -> anyhow::Result<()>{
    let options = MmapAreaOptions{ huge_tlb: false };
    let map_area = MmapArea::new(BUF_NUM, BUFF_SIZE, options);
    let (area, mut bufs) = match map_area {
        Ok((area, bufs)) => (area, bufs),
        Err(err) => panic!("no mmap for you: {:?}", err),
    };
    let mut rx_state = State::new(area.clone(), &mut bufs, StateType::Rx, interface.clone(), peer_map_fd);
    let rx = match rx_state.socket{
        SocketType::Rx(ref mut rx) => { Some(rx) }
        _ => None,
    };
    let rx = rx.unwrap();
    let custom = BufCustom {};
    loop {
        match rx.try_recv(&mut rx_state.v, BATCH_SIZE, custom) {
            Ok(n) => {
                if n > 0 {
                    while let Some(v) = rx_state.v.pop_front(){
                        let data: &[u8] = v.get_data();
                        if let Some(arp) = pnet::packet::arp::ArpPacket::new(&data[EthHdr::LEN..]){
                            match arp.get_operation(){
                                ArpOperations::Request => {
                                    let source_ip = arp.get_sender_proto_addr();
                                    let source_mac = arp.get_sender_hw_addr();
                                    let mut map = bpf.lock().unwrap();
                                    let map = map.map_mut("name").unwrap();
                                    let mut peer_map: HashMap<_, u32, u32> = HashMap::try_from(map)?;
                                    peer_map.insert(0, &0, 0);
                                }
                                _ => {}
                            }
                        }
                    }
                } else if rx_state.fq.needs_wakeup() {
                    rx.wake();
                }
            },
            Err(err) => {
                panic!("error: {:?}", err);
            }
        }
        if rx_state.fq_deficit >= BATCH_SIZE {
            let r = rx_state.fq.fill(&mut bufs, rx_state.fq_deficit);
            match r {
                Ok(n) => {
                    rx_state.fq_deficit -= n;
                }
                Err(err) => panic!("error: {:?}", err),
            }
        }
    }
}

pub async fn send_arp(ifaces: Vec<String>, interval: u64) -> anyhow::Result<()>{
    loop {
        for intf in &ifaces{
            let interfaces = datalink::interfaces();
            let interfaces_name_match = |iface: &NetworkInterface| iface.name == intf.clone();
            let interface = interfaces.into_iter().filter(interfaces_name_match).next().ok_or(anyhow!("interface not found"))?;
            let source_mac = interface.mac.ok_or(anyhow!("mac not found"))?;
            let target_mac = MacAddr::broadcast();
            let source_ip = interface.ips.iter().next().ok_or(anyhow!("ip not found"))?.ip();
            let source_ip = match source_ip{
                IpAddr::V4(v4) => v4,
                _ => return Err(anyhow!("ipv6 not supported")),
            };
            let target_ip = Ipv4Addr::BROADCAST;
            let(mut tx, _) = match datalink::channel(&interface, Default::default()) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unknown channel type"),
                Err(e) => panic!("Error happened {}", e),
            };
            let mut ethernet_buffer = [0u8; 42];
            let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        
            ethernet_packet.set_destination(target_mac);
            ethernet_packet.set_source(source_mac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);
        
            let mut arp_buffer = [0u8; 28];
            let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        
            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Request);
            arp_packet.set_sender_hw_addr(source_mac);
            arp_packet.set_sender_proto_addr(source_ip);
            arp_packet.set_target_hw_addr(target_mac);
            arp_packet.set_target_proto_addr(target_ip);
        
            ethernet_packet.set_payload(arp_packet.packet_mut());
        
            tx.send_to(&ethernet_packet.packet_mut(), Some(interface));
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}