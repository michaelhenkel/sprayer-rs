use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
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
                let bth_hdr: *const BthHdr = &buf[..n] as *const _ as *const BthHdr; 
                let bth_hdr: BthHdr = unsafe { *bth_hdr };
                let dst_qp_list = bth_hdr.dest_qpn;
                let dst_qp = u32::from_be_bytes([0, dst_qp_list[0], dst_qp_list[1], dst_qp_list[2]]);
                let seq_list = bth_hdr.psn_seq;
                let seq = u32::from_be_bytes([0, seq_list[0], seq_list[1], seq_list[2]]);
                let op_code = u8::from_be(bth_hdr.opcode);
                println!("opcode: {}, qp: {}, seq: {}", op_code, dst_qp, seq);
                if prev_seq > 0 {
                    if prev_seq + 1 != seq {
                        println!("seq error: prev: {}, curr: {}", prev_seq, seq);
                    }
                }
                prev_seq = seq;
                packets += 1;
                
                println!("received {} packets", packets);
                
            }
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