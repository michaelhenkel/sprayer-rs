use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, maps::Array};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use common::Ports;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "1")]
    links: u16,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut tc_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tc-egress"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut tc_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tc-egress"
    ))?;
    if let Err(e) = BpfLogger::init(&mut tc_bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let tc_program: &mut SchedClassifier = tc_bpf.program_mut("tc_egress").unwrap().try_into()?;
    tc_program.load()?;
    tc_program.attach(&opt.iface, TcAttachType::Egress)?;

    #[cfg(debug_assertions)]
    let mut xdp_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-ingress"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut xdp_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-ingress"
    ))?;
    if let Err(e) = BpfLogger::init(&mut xdp_bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let xdp_program: &mut Xdp = xdp_bpf.program_mut("xdp_ingress").unwrap().try_into()?;
    xdp_program.load()?;
    xdp_program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    if let Some(links) = tc_bpf.map_mut("LINKS"){
        let mut link_map: HashMap<_, u16, u16> = HashMap::try_from(links)?;
        link_map.insert(&0, &opt.links, 0)?;
    } else {
        warn!("LINKS map not found");
    }

    if let Some(counter) = tc_bpf.map_mut("COUNTER"){
        let mut counter_map: HashMap<_, u16, u16> = HashMap::try_from(counter)?;
        counter_map.insert(&0, &0, 0)?;
    } else {
        warn!("COUNTER map not found");
    }
    
    if let Some(port_list) = tc_bpf.map_mut("PORTS"){
        let mut port_map: HashMap<_, u16, u16> = HashMap::try_from(port_list)?;
        for link in 0..opt.links{
            let port = 1000 + link;
            port_map.insert(&link, &port,0)?;
        }
    } else {
        warn!("PORTS map not found");
    }
    
    

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
