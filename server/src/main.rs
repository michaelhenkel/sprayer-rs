use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use std::collections::{HashSet, HashMap};
use std::{io, any};
use clap::Parser;
use common::BthHdr;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "4791")]
    port: u16,
    #[clap(short, long, default_value = "lima1")]
    iface: String,
    #[clap(short, long, default_value = "reorder")]
    reorder: Option<bool>,
}


fn bth_from_bytes(bytes: &[u8]) -> BthHdr {
    let opcode = bytes[0];
    let sol_event = bytes[1];
    let part_key = u16::from_be_bytes([bytes[2], bytes[3]]);
    let res = bytes[4];
    let dest_qpn = [bytes[5], bytes[6], bytes[7]];
    let ack = bytes[8];
    let psn_seq = [bytes[9], bytes[10], bytes[11]];
    
    BthHdr { opcode, sol_event, part_key, res, dest_qpn, ack, psn_seq }
}


// fn get_get_ip_address_from_interface gets the ip address from the interface
// specified by the iface parameter.
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
    let ip = get_get_ip_address_from_interface(&opt.iface).unwrap();
    let reorder = if let Some(reorder) = opt.reorder {
        reorder
    } else {
        false
    };
    println!("Starting server on portx {}:{}", ip, opt.port);

    let (tx, rx) = tokio::sync::mpsc::channel(10000);
    let tx = tx.clone();

    let wait = vec![
        tokio::spawn(run_udp_server(opt.port, ip.to_string(), reorder, tx)),
        tokio::spawn(packet_counter(rx)),
    ];

    for t in wait {
        t.await.expect("server failed").unwrap();
    }
}

async fn run_udp_server(port: u16, ip: String, reorder: bool, packet_sender: tokio::sync::mpsc::Sender<Vec<u8>>) -> Result<(), Box<dyn std::error::Error + Send>> {
    
    let bindaddr = format!("{}:{}", ip, port);
    let sock = UdpSocket::bind(&bindaddr).await.unwrap();
    println!("listening on {}", bindaddr);

    //let mut buf = [0; 4];
    let mut prev_seq = 0;
    let mut packets = 0;
    let mut out_of_order_packets = 0;
    let mut total_bytes = 0;
    let mut start = tokio::time::Instant::now();
    let mut new_round = true;
    let mut end_of_round = false;
    let mut ooo_packets = Vec::new();
    let mut timer = tokio::time::Instant::now();
    let mut buffer = HashMap::new();
    let mut last_seq = 0;
    loop {
        
        // Wait for the socket to be readable
        sock.readable().await.unwrap();

        // The buffer is **not** included in the async task and will
        // only exist on the stack.
        let mut buf = [0; 1024];

        // Try to recv data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        
        match sock.try_recv(&mut buf) {
            Ok(n) => {

                if new_round {
                    start = tokio::time::Instant::now();
                    new_round = false;
                    println!("Starting new round");
                }
                //timer = tokio::time::Instant::now();
                let bth_hdr: BthHdr = bth_from_bytes(&buf[..n]);
                let dst_qp_list = bth_hdr.dest_qpn;
                let dst_qp = u32::from_be_bytes([0, dst_qp_list[0], dst_qp_list[1], dst_qp_list[2]]);
                let seq_list = bth_hdr.psn_seq;
                let seq = u32::from_be_bytes([0, seq_list[0], seq_list[1], seq_list[2]]);
                let res = u8::from_be(bth_hdr.res);
                if prev_seq > 0 {
                    if prev_seq + 1 != seq {
                        ooo_packets.push((prev_seq+1, seq));
                        out_of_order_packets += 1;
                        if reorder {
                            buffer.insert((dst_qp, seq), buf[..n].to_vec());
                        }
                    }
                }
                packet_sender.send(buf[..n].to_vec()).await.unwrap();
                prev_seq = seq;
                packets += 1;
                total_bytes += n;

                if res == 1 {
                    end_of_round = true;
                }                
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(Box::new(e));
            }
        }
        if end_of_round {
            let elapsed = start.elapsed().as_secs_f64();
            let mbps = (total_bytes as f64 * 8.0) / 1_000_000.0 / elapsed;
            let total_megabytes = total_bytes as f64 / 1_000_000.0;
            println!("{} packets received, {} out of order packets, {} MB received, {} MB/s", packets, out_of_order_packets, total_megabytes, mbps as u64);
            if ooo_packets.len() > 0 {
                println!("Out of order packets");
                for (start, end) in &ooo_packets{
                    println!("expected {} - got {}", start, end);
                }
            }
            ooo_packets.clear();
            end_of_round = false;
            new_round = true;
            prev_seq = 0;
            packets = 0;
            out_of_order_packets = 0;
            total_bytes = 0;
        }
    }
    Ok(())
}

async fn packet_counter(mut packet_receiver: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<(), Box<dyn std::error::Error + Send>>  {
    while let Some(packet) = packet_receiver.recv().await {
        println!("received {}",String::from_utf8_lossy(&packet));
    }
    Ok(())
}