use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags, ProgramFd, self};
use aya::{include_bytes_aligned, Bpf, maps::Array};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use common::NetworkKey;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::raw::c_int;
use std::io::{Error, ErrorKind};
use nix::ifaddrs::{getifaddrs, InterfaceAddress};


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

    let next_hop_map = std::collections::HashMap::from([
        ("10.0.0.2".to_string(), "192.168.0.2".to_string()),
        ("10.0.0.1".to_string(), "192.168.0.1".to_string())
    ]);

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


    let mut ebpf_shared = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-dummy"
    ))?;

    //let p: &mut programs:: = ebpf_shared.program_mut("name").unwrap().try_into()?;;
    //p.load()?;

    let intf_list = get_mac_addresses_and_interface_indexes();

    let mac_address = "de:ad:be:ef:ba:be";
    let bytes: Vec<u8> = mac_address
        .split(':')
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect();
    let mut proxy_mac_addr: [u8; 6] = [0; 6];
    proxy_mac_addr.copy_from_slice(&bytes[..]);
    proxy_mac_addr.reverse();

    match opt.mode{
        Mode::Encap => {
            info!("encap mode");
            let ifidx = get_interface_index(&opt.phy)?;
            info!("phy ifidx {}", ifidx);
            let phy_intf_addr = if let Some(addr) = get_interface_ip_address(&opt.phy){
                    addr
            } else {
                warn!("failed to find ip");
                return Ok(())
            };
            info!("phy intf addr {}", phy_intf_addr);
            
            
            if let Err(e) = BpfLogger::init(&mut xdp_encap_bpf) {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger: {}", e);
            }
            let xdp_program: &mut Xdp = xdp_encap_bpf.program_mut("xdp_encap").unwrap().try_into()?;
            xdp_program.load()?;


            xdp_program.attach(&opt.iface, XdpFlags::DRV_MODE)
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::DRV_MODE")?;
            
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

            if let Some(proxy_mac) = xdp_encap_bpf.map_mut("PROXYMAC"){
                let mut proxy_mac: HashMap<_, u8, [u8;6]> = HashMap::try_from(proxy_mac)?;
                proxy_mac.insert(&0, &proxy_mac_addr, 0)?;
            } else {
                warn!("DEVMAP map not found");
            }
             
            if let Some(nw_map) = xdp_encap_bpf.map_mut("NETWORKS"){
                let mut nw_map: HashMap<_, NetworkKey, u32> = HashMap::try_from(nw_map)?;
                let prefix: Ipv4Addr = "10.0.0.0".parse()?;
                let prefix_int = u32::from_be_bytes(prefix.octets());
                let key = NetworkKey{
                    prefix: prefix_int,
                    prefix_len: 24,
                };
                let gateway: Ipv4Addr = "10.0.0.1".parse()?;
                let gateway_int = u32::from_be_bytes(gateway.octets());

                nw_map.insert(&key, &gateway_int, 0)?;
            } else {
                warn!("NETWORKS map not found");
            }

            for (dst, nh) in &next_hop_map{
                let dst_addr: Ipv4Addr = dst.parse()?;
                let dst_int = u32::from_be_bytes(dst_addr.octets());
                let nh_addr: Ipv4Addr = nh.parse()?;
                let nh_int = u32::from_be_bytes(nh_addr.octets());
                if let Some(nh_map) = xdp_encap_bpf.map_mut("NEXTHOP"){
                    let mut nh_map: HashMap<_, u32, u32> = HashMap::try_from(nh_map)?;
                    nh_map.insert(&dst_int, &nh_int, 0)?;
                } else {
                    warn!("NEXTHOP map not found");
                }
            }

            if let Some(phy_ip) = xdp_encap_bpf.map_mut("PHYIP"){
                let mut phy_ip: HashMap<_, u8, u32> = HashMap::try_from(phy_ip)?;
                phy_ip.insert(&0, &phy_intf_addr, 0)?;
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
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::DRV_MODE")?;           
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
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::DRV_MODE")?;
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

fn get_interface_ip_address(interface_name: &str) -> Option<u32> {
    if let Ok(ifaddrs) = getifaddrs() {
        for ifaddr in ifaddrs {
            if ifaddr.interface_name == interface_name {
                if let Some(address) = ifaddr.address {
                    if let Some(ip_address) = address.as_sockaddr_in() {
                        return Some(ip_address.ip())
                    }
                }
            }
        }
    }
    None
}