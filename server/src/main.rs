use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use std::collections::HashSet;
use std::io;
use clap::Parser;
use common::BthHdr;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "4791")]
    port: u16,
    #[clap(short, long, default_value = "lima1")]
    iface: String,
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
    println!("Starting server on portx {}:{}", ip, opt.port);
    let wait = vec![
        tokio::spawn(run_udp_server(opt.port, ip.to_string())),
        tokio::spawn(run_tcp_server(opt.port, ip.to_string())),
    ];

    for t in wait {
        t.await.expect("server failed").unwrap();
    }
}

async fn run_udp_server(port: u16, ip: String) -> io::Result<()> {
    
    let bindaddr = format!("{}:{}", ip, port);
    let sock = UdpSocket::bind(&bindaddr).await?;
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
    loop {
        // Wait for the socket to be readable
        sock.readable().await?;

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
                }
                let bth_hdr: *const BthHdr = &buf[..n] as *const _ as *const BthHdr; 
                let bth_hdr: BthHdr = unsafe { *bth_hdr };
                let dst_qp_list = bth_hdr.dest_qpn;
                let dst_qp = u32::from_be_bytes([0, dst_qp_list[0], dst_qp_list[1], dst_qp_list[2]]);
                let seq_list = bth_hdr.psn_seq;
                let seq = u32::from_be_bytes([0, seq_list[0], seq_list[1], seq_list[2]]);
                let op_code = u8::from_be(bth_hdr.opcode);
                let res = u8::from_be(bth_hdr.res);
                if prev_seq > 0 {
                    if prev_seq + 1 != seq {
                        ooo_packets.push((prev_seq+1, seq));
                        out_of_order_packets += 1;
                    }
                }
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
                return Err(e);
            }
        }

        if end_of_round{
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

async fn run_tcp_server(port: u16, ip: String) -> io::Result<()> {
    let addr = format!("{}:{}", ip, port);
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);
    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            loop {
                let n = socket
                    .read(&mut buf)
                    .await
                    .expect("failed to read data from socket");

                if n == 0 {
                    return;
                }
                println!("received {}",String::from_utf8_lossy(&buf));

                socket
                    .write_all(&buf[0..n])
                    .await
                    .expect("failed to write data to socket");
            }
        });
    }
}