use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags, ProgramFd,self};
use aya::{include_bytes_aligned, Bpf, maps::Array};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use common::Interface;

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::io::{Error, ErrorKind};
use nix::ifaddrs::{getifaddrs, InterfaceAddress};
/*
use xsk_rs::{RxQueue, TxQueue, FrameDesc};
use xsk_rs::{
    config::{SocketConfig, UmemConfig},
    Socket, Umem,
};
*/
use arraydeque::{ArrayDeque, Wrapping};
use afxdp::mmap_area::{MmapArea, MmapAreaOptions};
use afxdp::socket::{Socket, SocketOptions, SocketRx, SocketTx};
use afxdp::umem::{Umem, UmemCompletionQueue, UmemFillQueue};
use afxdp::PENDING_LEN;
use afxdp::{buf::Buf, buf_pool::BufPool};
use afxdp::{buf_mmap::BufMmap, buf_pool_vec::BufPoolVec};
use libbpf_sys::{XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS};

const BUF_NUM: usize = 65536;
const BUF_LEN: usize = 4096;
const BATCH_SIZE: usize = 64;
struct XDPWorker<'a> {
    core: usize,
    rx: SocketRx<'a, BufCustom>,
    tx: SocketTx<'a, BufCustom>,
    cq: UmemCompletionQueue<'a, BufCustom>,
    fq: UmemFillQueue<'a, BufCustom>,
}

#[derive(Default, Copy, Clone)]
struct BufCustom {}

#[derive(clap::ValueEnum, Clone, Debug)]
enum Mode{
    EncapDecap,
    Dummy,
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
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    if (opt.encap.is_some() && opt.decap.is_none() || (opt.encap.is_none() && opt.decap.is_some())){
        panic!("encap and decap must be defined");
    }

    if opt.dummy.is_some() && (opt.decap.is_some() || opt.encap.is_some()){
        panic!("dummy cannot be defined with encap or decap");
    }



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

    #[cfg(debug_assertions)]
    let mut xdp_encap_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-encap"
    ))?;
    #[cfg(not(debug_assertions))]
    info!("load encap release");
    let mut xdp_encap_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-encap"
    ))?;

    #[cfg(debug_assertions)]
    let mut xdp_decap_bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-decap"
    ))?;
    #[cfg(not(debug_assertions))]
    info!("load decap release");
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

        if let Some(counter_map) = xdp_encap_bpf.map_mut("COUNTER"){
            let mut counter_map: HashMap<_, u8, u8> = HashMap::try_from(counter_map)?;
            counter_map.insert(&0, &0, 0)?;
        } else {
            warn!("COUNTER map not found");
        }

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

        let xdp_worker = get_socket(&decap_intf);
        /* 
        let (mut tx_queue, mut rx_queue, mut dev_desc) = get_socket(CString::new(decap_intf.clone()).unwrap());
        let tx_fd = tx_queue.fd().as_raw_fd() as u32;

        if let Some(xsk_map) = xdp_decap_bpf.map_mut("XSKMAP") {
            let mut xsk_map: HashMap<_, u32, u32> = HashMap::try_from(xsk_map)?;
            xsk_map.insert(&0, &tx_fd, 0)?;
        } else {
            warn!("XSKMAP map not found");
        }

        let pkts_recvd = unsafe { rx_queue.poll_and_consume(&mut dev_desc, 100).unwrap() };
        */


        //encap_decap(encap_intf, decap_intf, links)?
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
    } else {
        panic!("encap and decap or dummy must be defined");
    };

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

/*
fn get_socket(link_name: CString) -> (TxQueue, RxQueue, Vec<FrameDesc> ){
    let link = xsk_rs::config::Interface::new(link_name);
    let (dev1_umem, mut dev1_descs) = Umem::new(
        UmemConfig::default(), 
        32.try_into().unwrap(), 
        false
    )
    .expect("failed to create UMEM");
    let (mut dev1_tx_q, dev1_rx_q, _dev1_fq_and_cq) = Socket::new(
        SocketConfig::default(),
        &dev1_umem,
        &link,
        0,
    )
    .expect("failed to create dev1 socket");
    (dev1_tx_q, dev1_rx_q, dev1_descs)
}
*/

fn get_socket(link_name: &str) -> XDPWorker{
    let options = MmapAreaOptions { huge_tlb: false };
    let r = MmapArea::new(BUF_NUM, BUF_LEN, options);
    let (area, mut bufs) = match r {
        Ok((area, bufs)) => (area, bufs),
        Err(err) => panic!("Unable to create mmap for XDP load balancing: {:?}", err),
    };
    let mut bp: BufPoolVec<BufMmap<BufCustom>, BufCustom> = BufPoolVec::new(bufs.len());
    let len = bufs.len();
    let r = bp.put(&mut bufs, len);
    let r = Umem::new(
        area.clone(),
        XSK_RING_CONS__DEFAULT_NUM_DESCS,
        XSK_RING_PROD__DEFAULT_NUM_DESCS,
    );
    let (umem1, umem1cq, mut umem1fq) = match r {
        Ok(umem) => umem,
        Err(err) => panic!("Unable to create umem for XDP load balancing: {:?}", err),
    };
    let mut sock_opts = SocketOptions::default();
    sock_opts.copy_mode = true;
    let r = Socket::new(
        umem1.clone(),
        link_name,
        0,
        XSK_RING_CONS__DEFAULT_NUM_DESCS,
        XSK_RING_PROD__DEFAULT_NUM_DESCS,
        sock_opts,
    );
    let (_skt1, skt1rx, skt1tx) = match r {
        Ok(skt) => skt,
        Err(err) => {
            panic!("Unable to create socket for XDP load balancing: {:?}", err)
            
        }
    };
    let xdp_worker = XDPWorker{
        core: 0,
        rx: skt1rx,
        tx: skt1tx,
        cq: umem1cq,
        fq: umem1fq,
    };
    xdp_worker
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

impl XDPWorker<'_> {
    pub fn run(&mut self) {
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
                        debug!("XDP worker {:?} Received {:?} packets", self.core, n);
                        let r = self.process_packets(&mut v, &stats_sender);
                        match r {
                            Ok(_) => {}
                            Err(e) => error!("XDP: Problem processing packets: {:?}", e),
                        }
                        fq_deficit += n;
                    } else {
                        if self.fq.needs_wakeup() {
                            self.rx.wake();
                        }
                    }
                }
                Err(err) => {
                    error!("XDP: {:?}", err);
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