use anyhow::Context;
use aya::maps::{HashMap, XskMap};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, BpfLoader};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use common::{Interface, LinkCounter};

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, AsFd};
use std::io::{Error, ErrorKind};
use nix::ifaddrs::getifaddrs;



#[derive(Default, Copy, Clone)]
struct BufCustom {}


#[derive(clap::ValueEnum, Clone, Debug)]
enum Mode{
    EncapDecap,
    Dummy,
    Disco,
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    encap: Option<String>,
    #[clap(short, long)]
    decap: Option<String>,
    #[clap(short, long, default_value = "1")]
    links: u8,
    #[clap(short, long)]
    dummy: Option<String>,
    #[clap(short, long)]
    buffer: Option<bool>,
    #[clap(short, long)]
    factor: Option<u8>,
    #[clap(short, long)]
    disco: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    if opt.encap.is_some() && opt.decap.is_none() || (opt.encap.is_none() && opt.decap.is_some()){
        panic!("encap and decap must be defined");
    }

    if opt.dummy.is_some() && (opt.decap.is_some() || opt.encap.is_some() || opt.disco.is_some()){
        panic!("dummy cannot be defined with encap or decap");
    }

    if opt.disco.is_some() && (opt.decap.is_some() || opt.encap.is_some() || opt.dummy.is_some()){
        panic!("disco cannot be defined with encap or decap");
    }

    let buffer = match opt.buffer{
        Some(buffer) => { buffer },
        None => { true }
    };

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

    #[cfg(not(debug_assertions))]
    info!("load encap release");
    let mut xdp_encap_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-encap"
    ))?;

    /*
    #[cfg(debug_assertions)]
    let mut xdp_decap_bpf = Bpf::load(include_bytes_aligned!(
        "/tmp/lima/bpfel-unknown-none/debug/xdp-decap"
    ))?;
    #[cfg(not(debug_assertions))]
    info!("load decap release");
    let mut xdp_decap_bpf = Bpf::load(include_bytes_aligned!(
        "/tmp/lima/bpfel-unknown-none/release/xdp-decap"
    ))?;
    */
    

    //#[cfg(debug_assertions)]
    //let mut xdp_decap_bpf = BpfLoader::new().allow_unsupported_maps().load(
    //    include_bytes_aligned!(
    //        "/tmp/lima/bpfel-unknown-none/debug/xdp-decap"
    //    )
    //)?;

    #[cfg(not(debug_assertions))]
    info!("load decap release");
    let mut xdp_decap_bpf = BpfLoader::new().allow_unsupported_maps().load(
        include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/xdp-decap"
        )
    )?;

    //#[cfg(debug_assertions)]
    //let mut xdp_dummy_bpf = Bpf::load(include_bytes_aligned!(
    //    "/tmp/lima/bpfel-unknown-none/debug/xdp-dummy"
    //))?;
    #[cfg(not(debug_assertions))]
    info!("load dummy release");
    let mut xdp_dummy_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-dummy"
    ))?;

    #[cfg(not(debug_assertions))]
    info!("load peer disco release");
    let mut xdp_peer_disco_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-peer-disco"
    ))?;

    let res = if opt.decap.is_some() && opt.encap.is_some() {
        let encap_intf = opt.encap.unwrap();
        let decap_intf = opt.decap.unwrap();
        let links = opt.links;

        info!("encap/decap mode");
        let (encap_intf_mac, encap_intf_idx) = if let Some((encap_intf_mac, encap_intf_idx)) = get_mac_addresses_and_interface_index(&encap_intf){
            (encap_intf_mac, encap_intf_idx)
        } else {
            warn!("failed to find mac or idx for encap");
            return Ok(())
        };
    
        let (decap_intf_mac, decap_intf_idx) = if let Some((decap_intf_mac, decap_intf_idx)) = get_mac_addresses_and_interface_index(&decap_intf){
            (decap_intf_mac, decap_intf_idx)
        } else {
            warn!("failed to find mac or idx for decap");
            return Ok(())
        };
    
        let encap_intf_addr = if let Some(addr) = get_interface_ip_address(&encap_intf){
            addr
        } else {
            warn!("failed to find ip");
            return Ok(())
        };
    
        let decap_intf_addr = if let Some(addr) = get_interface_ip_address(&decap_intf){
            addr
        } else {
            warn!("failed to find ip");
            return Ok(())
        };

        if let Err(e) = BpfLogger::init(&mut xdp_encap_bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }
        info!("loading encap on interface {}", encap_intf);
        let encap_program: &mut Xdp = xdp_encap_bpf.program_mut("xdp_encap").unwrap().try_into()?;
        encap_program.load()?;
        encap_program.attach(&encap_intf, XdpFlags::DRV_MODE)
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::DRV_MODE")?;
        
        if let Some(decap_intf_map) = xdp_encap_bpf.map_mut("DECAPINTERFACE"){
            let mut decap_intf_map: HashMap<_, u32, Interface> = HashMap::try_from(decap_intf_map)?;
            let intf = Interface{
                mac: decap_intf_mac,
                ifidx: decap_intf_idx,
                ip: u32::to_be(decap_intf_addr),
            };
            decap_intf_map.insert(&0, &intf, 0)?;
        } else {
            warn!("DECAPINTERFACE map not found");
        }

        if let Some(links_map) = xdp_encap_bpf.map_mut("LINKS"){
            let mut links_map: HashMap<_, u8, u8> = HashMap::try_from(links_map)?;
            links_map.insert(&0, &links, 0)?;
        } else {
            warn!("LINKS map not found");
        }

        if let Some(buf_map) = xdp_encap_bpf.map_mut("BUFFER"){
            let mut buf_map: HashMap<_, u8, u8> = HashMap::try_from(buf_map)?;
            if buffer{
                buf_map.insert(&0, &1, 0)?;
            } else {
                buf_map.insert(&0, &0, 0)?;
            }
            
        } else {
            warn!("encap buf map not found");
        }

        if let Some(factor) = opt.factor{
            if let Some(link_counter_map) = xdp_encap_bpf.map_mut("LINKCOUNTER"){
                let mut link_counter_map: HashMap<_, u8, LinkCounter> = HashMap::try_from(link_counter_map)?;
                link_counter_map.insert(&0, &LinkCounter{links: factor,counter: 0}, 0)?;
            } else {
                warn!("LINKCOUNTER map not found");
            }
        }

        if let Some(counter_map) = xdp_encap_bpf.map_mut("COUNTER"){
            let mut counter_map: HashMap<_, u8, u8> = HashMap::try_from(counter_map)?;
            counter_map.insert(&0, &0, 0)?;
        } else {
            warn!("COUNTER map not found");
        }
        info!("loading decap on interface {}", decap_intf);
        if let Err(e) = BpfLogger::init(&mut xdp_decap_bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }
        let decap_program: &mut Xdp = xdp_decap_bpf.program_mut("xdp_decap").unwrap().try_into()?;
        decap_program.load()?;
        decap_program.attach(&decap_intf, XdpFlags::DRV_MODE)
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::DRV_MODE")?;  

        if let Some(encap_intf_map) = xdp_decap_bpf.map_mut("ENCAPINTERFACE"){
            let mut encap_intf_map: HashMap<_, u32, Interface> = HashMap::try_from(encap_intf_map)?;
            let intf = Interface{
                mac: encap_intf_mac,
                ifidx: encap_intf_idx,
                ip: u32::to_be(encap_intf_addr),
            };
            encap_intf_map.insert(&0, &intf, 0)?;
        } else {
            warn!("ENCAPINTERFACE map not found");
        }

        if let Some(factor) = opt.factor{
            if let Some(link_counter_map) = xdp_decap_bpf.map_mut("LINKCOUNTER"){
                let mut link_counter_map: HashMap<_, u8, LinkCounter> = HashMap::try_from(link_counter_map)?;
                link_counter_map.insert(&0, &LinkCounter{links: factor,counter: 0}, 0)?;
            } else {
                warn!("LINKCOUNTER map not found");
            }
        }

        if let Some(buf_map) = xdp_decap_bpf.map_mut("BUFFER"){
            let mut buf_map: HashMap<_, u8, u8> = HashMap::try_from(buf_map)?;
            if buffer{
                buf_map.insert(&0, &1, 0)?;
            } else {
                buf_map.insert(&0, &0, 0)?;
            }
            
        } else {
            warn!("decap buf map not found");
        }

        info!("load xsk map");
        let ingress_map_fd = if let Some(xsk_map) = xdp_decap_bpf.map("INGRESSXSKMAP") {
            let xsk_map = XskMap::<_, u32, u32>::try_from(xsk_map)?;
            xsk_map.fd().unwrap().as_fd().as_raw_fd()    
        } else {
            panic!("INGRESSXSKMAP map not found");
        };

        let egress_map_fd = if let Some(xsk_map) = xdp_encap_bpf.map_mut("EGRESSXSKMAP") {
            let xsk_map = XskMap::<_, u32, u32>::try_from(xsk_map)?;
            xsk_map.fd().unwrap().as_fd().as_raw_fd()    
        } else {
            panic!("EGRESSXSKMAP map not found");
        };
        /*
        let mut buf = Buffer::new(decap_intf.clone(), encap_intf.clone(), ingress_map_fd, egress_map_fd, xdp_decap_bpf, xdp_encap_bpf);

        match buf.run().await{
            Ok(_) => {},
            Err(e) => {
                panic!("error: {:?}", e);
            }
        }
        */


    } else if opt.dummy.is_some() {
        let dummy_intf = opt.dummy.unwrap();
        if let Err(e) = BpfLogger::init(&mut xdp_dummy_bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }
        let xdp_program: &mut Xdp = xdp_dummy_bpf.program_mut("xdp_dummy").unwrap().try_into()?;
        xdp_program.load()?;
        xdp_program.attach(&dummy_intf, XdpFlags::DRV_MODE)
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::DRV_MODE")?;
        //dummy(dummy_intf)?
    } else if opt.disco.is_some(){
        let disco_interfaces = opt.disco.unwrap();
    } else {
        panic!("encap and decap or dummy must be defined");
    };

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

fn get_mac_addresses_and_interface_index(interface_name: &str) -> Option<([u8; 6], u32)> {
    if let Ok(ifaddrs) = getifaddrs() {
        for ifaddr in ifaddrs {
            if ifaddr.interface_name == interface_name {
                let interface_index = match get_interface_index(&ifaddr.interface_name) {
                    Ok(index) => index,
                    Err(_) => continue,
                };
                if let Some(address) = ifaddr.address {
                    if let Some(link_address) = address.as_link_addr(){
                        if let Some(mac) = link_address.addr(){
                            return Some((mac, interface_index));
                        }
                    }
                }
            }

        }
    }
    None
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

fn mac_to_vec(mac: &str) -> [u8; 6]{
    let bytes: Vec<u8> = mac
        .split(':')
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect();
    let mut mac_addr: [u8; 6] = [0; 6];
    mac_addr.copy_from_slice(&bytes[..]);
    mac_addr
}

fn ip_to_dec(ip: &str) -> u32{
    let ip_addr: Ipv4Addr = ip.parse().unwrap();
    u32::from_be_bytes(ip_addr.octets())
}


/*
impl XDPWorker<'_> {
    pub async fn run(&mut self) {
        let mut v: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
        let custom = BufCustom {};
        let mut fq_deficit = 0;

        let core = core_affinity::CoreId { id: self.core };
        core_affinity::set_for_current(core);

        const START_BUFS: usize = 8192;

        let mut bufs = Vec::with_capacity(START_BUFS);

        // Fill the worker Umem
        let r = self.fq.fill(
            &mut bufs,
            min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM),
        );
        match r {
            Ok(n) => {
                if n != min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM) {
                    panic!(
                        "Initial fill of umem incomplete. Wanted {} got {}.",
                        BUF_NUM, n
                    );
                }
            }
            Err(err) => panic!("error: {:?}", err),
        }

        debug!("Starting XDP Loop");
        loop {
            //
            // Service completion queue
            //
            let r = self.cq.service(&mut bufs, BATCH_SIZE);
            match r {
                Ok(_) => {}
                Err(err) => panic!("error: {:?}", err),
            }

            // Receive ring
            let r = self.rx.try_recv(&mut v, BATCH_SIZE, custom);
            match r {
                Ok(n) => {
                    if n > 0 {
                        info!("XDP worker {:?} Received {:?} packets", self.core, n);
                        /*
                        let r = self.process_packets(&mut v, &stats_sender);
                        match r {
                            Ok(_) => {}
                            Err(e) => error!("XDP: Problem processing packets: {:?}", e),
                        }
                        */
                        fq_deficit += n;
                    } else {
                        if self.fq.needs_wakeup() {
                            self.rx.wake();
                        }
                    }
                }
                Err(err) => {
                    info!("XDP: {:?}", err);
                }
            }


            //
            // Fill buffers if required
            //
            if fq_deficit > 0 {
                let r = self.fq.fill(&mut bufs, fq_deficit);
                match r {
                    Ok(n) => {
                        fq_deficit -= n;
                    }
                    Err(err) => panic!("error: {:?}", err),
                }
            }
        }
    }
}
*/