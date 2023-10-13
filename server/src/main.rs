use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use libc::setsockopt;
use nix::sys::socket::{self, sockopt::RcvBuf};
//use socket2::{Socket, Domain, Type};
//use std::net::{SocketAddr, UdpSocket};

use std::collections::{HashSet, HashMap};
use std::{io, mem};
use std::os::fd::AsRawFd;
use clap::Parser;
use common::BthHdr;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "4791")]
    port: u16,
    #[clap(short, long, default_value = "lima1")]
    iface: String,
    #[clap(short, long, default_value = "512")]
    size: usize,
}

fn from_bytes(bytes: &[u8]) -> BthHdr {
    BthHdr {
        opcode: bytes[0],
        sol_event: bytes[1],
        part_key: u16::from_be_bytes([bytes[2], bytes[3]]),
        res: bytes[4],
        dest_qpn: [bytes[5], bytes[6], bytes[7]],
        ack: bytes[8],
        psn_seq: [bytes[9], bytes[10], bytes[11]],
    }
}

fn get_get_ip_address_from_interface(iface_name: &str) -> Result<std::net::IpAddr, anyhow::Error> {
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
async fn main() {
    let opt = Opt::parse();
    let packet_size = opt.size;
    let ip = get_get_ip_address_from_interface(&opt.iface).unwrap();
    println!("Starting server on portx {}:{}", ip, opt.port);
    let (tx, rx) = tokio::sync::mpsc::channel(100000);
    let wait = vec![
        tokio::spawn(handle_packet(rx)),
        tokio::spawn(run_udp_server(opt.port, ip.to_string(), tx, packet_size)),
    ];
    for t in wait {
        t.await.expect("server failed").unwrap();
    }
    
}

async fn run_udp_server(port: u16, ip: String, tx: tokio::sync::mpsc::Sender<(Vec<u8>, usize)>, packet_size: usize) -> io::Result<()> {
    
    let bindaddr = format!("{}:{}", ip, port);
    let sock = UdpSocket::bind(&bindaddr).await?;
    socket::setsockopt(&sock, RcvBuf, &(65535*1000)).unwrap();
    let mut v: Vec<u8> = Vec::with_capacity(packet_size);
    //let mut s = v.as_mut_slice();
    let mut b = [0u8; 1024];
    println!("listening on {}", bindaddr);
    loop {
        match sock.try_recv(&mut b){
            Ok(n) => {
                let v = b.to_vec();
                if let Err(e) = tx.send((v, n)).await{
                    println!("error sending to handler: {}", e);
                }
            },
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e);
            }

        }
    }
    Ok(())
}

async fn handle_packet(mut rx: tokio::sync::mpsc::Receiver<(Vec<u8>, usize)>) -> io::Result<()> {
    println!("starting packet handler");
    let mut prev_seq = 0;
    let mut packets = 0;
    let mut out_of_order_packets = 0;
    let mut total_bytes = 0;
    let mut start = tokio::time::Instant::now();
    let mut new_round = true;
    let mut end_of_round = false;
    let mut first_seq = 0;
    let mut last_seq = 0;
    let mut first_packet = true;

    loop {
        match rx.try_recv(){
            Ok((buf, n)) => {
                if new_round {
                    start = tokio::time::Instant::now();
                    new_round = false;
                    first_seq = 0;
                    println!("Starting new round");
                    first_packet = true;
                }
                let bth_hdr: *const BthHdr = &buf[..n] as *const _ as *const BthHdr; 
                let bth_hdr: BthHdr = unsafe { *bth_hdr };
                let seq_list = bth_hdr.psn_seq;
                let seq = u32::from_be_bytes([0, seq_list[0], seq_list[1], seq_list[2]]);
                let res = u8::from_be(bth_hdr.res);
                if prev_seq > 0 {
                    if prev_seq + 1 != seq {
                        out_of_order_packets += 1;
                    }
                }
                if first_packet {
                    first_seq = seq;
                    first_packet = false;
                }
                prev_seq = seq; 
                packets += 1;
                total_bytes += n;
                if res == 1 {
                    last_seq = seq;
                    end_of_round = true;
                }
                if end_of_round {
                    let elapsed = start.elapsed().as_secs_f64();
                    let mbps = (total_bytes as f64 * 8.0) / 1_000_000.0 / elapsed;
                    let total_megabytes = total_bytes as f64 / 1_000_000.0;
                    let pps = packets as f64 / elapsed;
                    let packet_loss = (last_seq - first_seq) - packets as u32 + 1;
                    println!("{} packets received, {} out of order packets, {} MB received, {} MB/s, {} pps, {} lost packets", packets, out_of_order_packets, total_megabytes, mbps as u64, pps as u64, packet_loss);
                    end_of_round = false;
                    new_round = true;
                    prev_seq = 0;
                    packets = 0;
                    out_of_order_packets = 0;
                    total_bytes = 0;
                } 
            },
            Err(e) => {
                //return Err(e.into());
            }
        }

        /*
        while let Some((buf, n)) = rx.recv().await{
            println!("received {} bytes", n);
            if new_round {
                start = tokio::time::Instant::now();
                new_round = false;
                first_seq = 0;
                println!("Starting new round");
                first_packet = true;
            }
            let bth_hdr: *const BthHdr = &buf[..n] as *const _ as *const BthHdr; 
            let bth_hdr: BthHdr = unsafe { *bth_hdr };
            let seq_list = bth_hdr.psn_seq;
            let seq = u32::from_be_bytes([0, seq_list[0], seq_list[1], seq_list[2]]);
            let res = u8::from_be(bth_hdr.res);
            if prev_seq > 0 {
                if prev_seq + 1 != seq {
                    out_of_order_packets += 1;
                }
            }
            if first_packet {
                first_seq = seq;
                first_packet = false;
            }
            prev_seq = seq; 
            packets += 1;
            total_bytes += n;
            if res == 1 {
                last_seq = seq;
                end_of_round = true;
            }
            if end_of_round {
                let elapsed = start.elapsed().as_secs_f64();
                let mbps = (total_bytes as f64 * 8.0) / 1_000_000.0 / elapsed;
                let total_megabytes = total_bytes as f64 / 1_000_000.0;
                let pps = packets as f64 / elapsed;
                let packet_loss = (last_seq - first_seq) - packets as u32 + 1;
                println!("{} packets received, {} out of order packets, {} MB received, {} MB/s, {} pps, {} lost packets", packets, out_of_order_packets, total_megabytes, mbps as u64, pps as u64, packet_loss);
                end_of_round = false;
                new_round = true;
                prev_seq = 0;
                packets = 0;
                out_of_order_packets = 0;
                total_bytes = 0;
            } 

        }
        */
    }
    Ok(())
}