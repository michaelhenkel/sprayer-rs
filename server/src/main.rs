use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use std::io;
use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "3000")]
    port: u16,
    #[clap(short, long, default_value = "veth1")]
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

    let mut buf = [0; 4];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("port {}: {} bytes received from {}", port, len, addr);
        println!(
            "port {}: buffer contents: {}",
            port,
            String::from_utf8_lossy(&buf)
        );
    }
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