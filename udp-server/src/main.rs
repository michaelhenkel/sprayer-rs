use std::io;
use tokio::net::UdpSocket;
use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "3000")]
    port: u16,
}

#[tokio::main]
async fn main() {
    let opt = Opt::parse();
    let wait = vec![
        tokio::spawn(run_server(opt.port)),
    ];

    for t in wait {
        t.await.expect("server failed").unwrap();
    }
}

async fn run_server(port: u16) -> io::Result<()> {
    let bindaddr = format!("10.0.0.2:{}", port);
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