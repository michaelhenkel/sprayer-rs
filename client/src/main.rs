use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use std::{io, any, net::SocketAddr};
use clap::Parser;
use common::BthHdr;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use netlink_packet_route::{
    constants::*, packet::route::RouteMessage, NetlinkMessage, RtnlMessage,
};
use std::net::IpAddr;


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "192.168.1.102:4791")]
    dst: String,
    #[clap(short, long, default_value = "veth1")]
    iface: String,
}

// specified by the iface parameter.
fn get_ip_address_from_interface(iface_name: &str) -> Result<std::net::IpAddr, anyhow::Error> {
    let iface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == iface_name)
        .ok_or(anyhow::anyhow!("interface not found"))?;
    let ip = iface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .ok_or(anyhow::anyhow!("interface has no ipv4 address"))?
        .ip();
    Ok(ip)
}

#[tokio::main]
async fn main() -> anyhow::Result<()>{
    let opt = Opt::parse();
    let ip = get_ip_address_from_interface(&opt.iface).unwrap();
    let ip_port = format!("{}:{}", ip.to_string(), random_src_port());
    let mac = get_mac_address_from_interface(&opt.iface).unwrap();
    
    let mut sock = UdpSocket::bind(ip_port).await.unwrap();
    let remote_addr = opt.dst.parse::<SocketAddr>().unwrap();
    sock.connect(remote_addr).await?;
    let mut buf = [0u8; 32];
    // send to remote_addr
    //let _len = sock.send(&buf[..len]).await?;
    
    Ok(())
}

fn random_src_port() -> u16 {
    rand::random::<u16>()
}


