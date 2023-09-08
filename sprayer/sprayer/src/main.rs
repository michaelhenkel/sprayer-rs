use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, maps::Array};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use common::Ports;
use std::ffi::CString;
use std::os::raw::c_int;
use std::io::{Error, ErrorKind};
use nix::ifaddrs::getifaddrs;


#[derive(clap::ValueEnum, Clone, Debug)]
enum Mode{
    Encap,
    Decap,
    Dummy,
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "eth0")]
    phy: String,
    #[clap(short, long, default_value = "1")]
    links: u16,
    #[clap(value_enum)]
    mode: Mode,
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
    info!("starting...");

    #[cfg(debug_assertions)]
    let mut xdp_encap_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-encap"
    ))?;
    #[cfg(not(debug_assertions))]
    info!("load release");
    let mut xdp_encap_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-encap"
    ))?;

    #[cfg(debug_assertions)]
    let mut xdp_decap_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-decap"
    ))?;
    #[cfg(not(debug_assertions))]
    info!("load release");
    let mut xdp_decap_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-decap"
    ))?;


    #[cfg(debug_assertions)]
    let mut xdp_dummy_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-dummy"
    ))?;
    #[cfg(not(debug_assertions))]
    info!("load release");
    let mut xdp_dummy_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-dummy"
    ))?;

    let intf_list = get_mac_addresses_and_interface_indexes();

    match opt.mode{
        Mode::Encap => {
            info!("encap mode");
            let ifidx = get_interface_index(&opt.phy)?;
            info!("phy ifidx {}", ifidx);

            
            if let Err(e) = BpfLogger::init(&mut xdp_encap_bpf) {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger: {}", e);
            }
            let xdp_program: &mut Xdp = xdp_encap_bpf.program_mut("xdp_encap").unwrap().try_into()?;
            xdp_program.load()?;


            xdp_program.attach(&opt.iface, XdpFlags::SKB_MODE)
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
            
            if let Some(phy_intf_map) = xdp_encap_bpf.map_mut("PHYINTF"){
                let mut phy_intf_map: HashMap<_, u8, u32> = HashMap::try_from(phy_intf_map)?;
                phy_intf_map.insert(&0, &ifidx, 0)?;
            } else {
                warn!("LINKS map not found");
            }
            if let Some(dev_map) = xdp_encap_bpf.map_mut("DEVMAP"){
                let mut dev_map: HashMap<_, [u8;6], u32> = HashMap::try_from(dev_map)?;
                for (k,v) in intf_list{
                    dev_map.insert(&k, &v, 0)?;
                }  
            } else {
                warn!("DEVMAP map not found");
            }
        },
        Mode::Dummy => {
            info!("dummy mode");
            if let Err(e) = BpfLogger::init(&mut xdp_dummy_bpf) {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger: {}", e);
            }
            let xdp_program: &mut Xdp = xdp_dummy_bpf.program_mut("xdp_dummy").unwrap().try_into()?;
            xdp_program.load()?;
            xdp_program.attach(&opt.iface, XdpFlags::DRV_MODE)
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;           
        }
        Mode::Decap => {
            info!("decap mode");
            if let Err(e) = BpfLogger::init(&mut xdp_decap_bpf) {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger: {}", e);
            }
            let xdp_program: &mut Xdp = xdp_decap_bpf.program_mut("xdp_decap").unwrap().try_into()?;
            xdp_program.load()?;
            xdp_program.attach(&opt.iface, XdpFlags::DRV_MODE)
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
        },
    }





    /*
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
    */
    
    

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn get_interface_index(interface_name: &str) -> Result<u32, Error> {
    let interface_name_cstring = CString::new(interface_name)?;
    let interface_index = unsafe { libc::if_nametoindex(interface_name_cstring.as_ptr()) };
    if interface_index == 0 {
        Err(Error::new(ErrorKind::NotFound, "Interface not found"))
    } else {
        Ok(interface_index)
    }
}

fn get_mac_addresses_and_interface_indexes() -> Vec<([u8; 6], u32)> {
    let mut mac_addresses_and_interface_indexes = Vec::new();
    if let Ok(ifaddrs) = getifaddrs() {
        for ifaddr in ifaddrs {
            let interface_index = match get_interface_index(&ifaddr.interface_name) {
                Ok(index) => index,
                Err(_) => continue,
            };
            if let Some(address) = ifaddr.address {
                if let Some(link_address) = address.as_link_addr(){
                    if let Some(mac) = link_address.addr(){
                        mac_addresses_and_interface_indexes.push((mac, interface_index));
                    }
                }
            }
        }
    }
    mac_addresses_and_interface_indexes
}