#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{xdp_action, self},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_fib_lookup, bpf_redirect},
    programs::XdpContext,
    maps::HashMap,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto, self},
    udp::UdpHdr,
};
use core::mem::{self, MaybeUninit};
use core::mem::{size_of, zeroed};
use aya_bpf::cty::c_void;
use common::NetworkKey;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct ArpHdr{
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sha: [u8;6],
    spa: u32,
    tha: [u8;6],
    tpa: u32,
}

impl ArpHdr {
    pub const LEN: usize = mem::size_of::<ArpHdr>();
}

#[map(name = "PHYINTF")]
static mut PHYINTF: HashMap<u8, u32> =
    HashMap::<u8, u32>::with_max_entries(1, 0);


#[map(name = "NETWORKS")]
static mut NETWORKS: HashMap<NetworkKey, u32> =
    HashMap::<NetworkKey, u32>::with_max_entries(100, 0);

#[map(name = "DEVMAP")]
static mut DEVMAP: HashMap<[u8;6], u32> =
    HashMap::<[u8;6], u32>::with_max_entries(10, 0);

#[map(name = "PROXYMAC")]
static mut PROXYMAC: HashMap<u8, [u8;6]> =
    HashMap::<u8, [u8;6]>::with_max_entries(1, 0);

#[map(name = "NEXTHOP")]
static mut NEXTHOP: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(256, 0);

#[map(name = "PHYIP")]
static mut PHYIP: HashMap<u8, u32> =
    HashMap::<u8, u32>::with_max_entries(1, 0);

#[xdp]
pub fn xdp_encap(ctx: XdpContext) -> u32 {
    let phy_intf = match unsafe { PHYINTF.get(&0) } {
        Some(phy_intf) => {
            phy_intf
        }
        None => {
            info!(&ctx, "phy intf not found");
            return xdp_action::XDP_ABORTED
        }
    };
    match try_xdp_encap(ctx, *phy_intf) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_encap(ctx: XdpContext, phy_intf: u32) -> Result<u32, u32> {
    info!(&ctx, "xdp_encap");
    let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;

    let mut outer_eth_hdr = unsafe { eth_hdr.read() };

    let (hdr_len, payload_len, phy_ifidx) = match unsafe{ (*eth_hdr).ether_type } {
        EtherType::Arp => {
            info!(&ctx, "arp");
            let arp_hdr = ptr_at_mut::<ArpHdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
            let oper = u16::from_be(unsafe{ (*arp_hdr).oper });
            if oper == 1 {
                info!(&ctx, "arp request");                
                let dst_addr = u32::from_be(unsafe{ (*arp_hdr).tpa });
                let src_addr = u32::from_be(unsafe{ (*arp_hdr).spa });
                let src_mac = unsafe { (*arp_hdr).sha };
                let proxy_mac = match unsafe { PROXYMAC.get(&0) } {
                    Some(proxy_mac) => proxy_mac,
                    None => {
                        info!(&ctx, "proxy mac not found");
                        return Ok(xdp_action::XDP_ABORTED);
                    }
                };
                let pm = proxy_mac.clone();
                outer_eth_hdr.src_addr = proxy_mac.clone();
                outer_eth_hdr.dst_addr = src_mac;
                unsafe { (*arp_hdr).oper = u16::from_be(2) };
                unsafe { (*arp_hdr).spa = u32::from_be(dst_addr)}
                unsafe { (*arp_hdr).tpa = u32::from_be(src_addr)}
                unsafe { (*arp_hdr).tha = src_mac};
                unsafe { (*arp_hdr).sha = pm};
                unsafe { eth_hdr.write(outer_eth_hdr);};
                info!(&ctx, "replying");
                return Ok(xdp_action::XDP_TX);
            }
            
            return Ok(xdp_action::XDP_PASS);

        },
        EtherType::Ipv4 => {
            let ip_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
            
            let ip_proto = unsafe { (*ip_hdr_ptr).proto };
            match ip_proto {
                IpProto::Tcp => {},
                IpProto::Udp => {},
                IpProto::Icmp => {},
                _ => {
                    let ipp = ip_proto as u8;
                    info!(&ctx,"ip_proto not tcp or udp, {} passing", ipp);
                    return Ok(xdp_action::XDP_PASS)
                }
            }
            let dst_ip = unsafe { (*ip_hdr_ptr).dst_addr };
            let if_idx = unsafe { (*ctx.ctx).ingress_ifindex };

            let nh = match unsafe { NEXTHOP.get(&u32::from_be(dst_ip)) } {
                Some(nh) => {
                    nh.clone()
                }
                None => {
                    info!(&ctx, "nh not found");
                    return Ok(xdp_action::XDP_ABORTED)
                }
            };
            info!(&ctx, "nh: {}", nh);
            let phy_ip = match unsafe { PHYIP.get(&0) } {
                Some(phy_ip) => {
                    phy_ip.clone()
                }
                None => {
                    info!(&ctx, "phy_ip");
                    return Ok(xdp_action::XDP_ABORTED)
                }
            };
            info!(&ctx, "phy_ip: {}", phy_ip);
            let mut params: bindings::bpf_fib_lookup = unsafe { zeroed() };
            params.family = 2;
            params.ifindex = phy_intf;
            params.__bindgen_anon_4.ipv4_dst = u32::from_be(nh);
            let params_ptr: *mut bindings::bpf_fib_lookup = &mut params as *mut _;

            let param_size = size_of::<bindings::bpf_fib_lookup>();
            info!(&ctx, "param_size: {}", param_size);
        
            let ctx_ptr = ctx.ctx as *mut _ as *mut c_void;
            let ret: i64 = unsafe {
                bpf_fib_lookup(ctx_ptr, params_ptr, 64, 0)
            };
            if ret != 0 {
                info!(&ctx,"fib lookup failed for dst ip {:i}, ifidx {}, ret {}",dst_ip, if_idx, ret);
                return Ok(xdp_action::XDP_DROP);
            }
            
            outer_eth_hdr.dst_addr = params.dmac;
            outer_eth_hdr.src_addr = params.smac;

            let mut outer_ip_hdr = unsafe { ip_hdr_ptr.read() };
            let new_ip_hdr_tot_len = u16::from_be(outer_ip_hdr.tot_len) + (EthHdr::LEN  + Ipv4Hdr::LEN + UdpHdr::LEN) as u16;
            outer_ip_hdr.tot_len = u16::to_be(new_ip_hdr_tot_len);
            outer_ip_hdr.proto = IpProto::Udp;
            outer_ip_hdr.dst_addr = unsafe { params.__bindgen_anon_4.ipv4_dst };
            outer_ip_hdr.src_addr = u32::to_be(phy_ip);
            unsafe {
                bpf_xdp_adjust_head(ctx.ctx, -((EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as i32));
            }
            let outer_ip_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
            unsafe { 
                outer_ip_ptr.write(outer_ip_hdr);
            };

            let eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
            unsafe { eth_hdr_ptr.write(outer_eth_hdr) };


    
            (Ipv4Hdr::LEN, new_ip_hdr_tot_len - Ipv4Hdr::LEN as u16, params.ifindex)
        },
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let outer_udp_hdr = UdpHdr{
        source: u16::to_be(1000),
        dest: u16::to_be(3000),
        len: u16::to_be(payload_len),
        check: 0,
    };
    let udp_hdr_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + hdr_len).ok_or(xdp_action::XDP_PASS)?;
    unsafe { udp_hdr_ptr.write(outer_udp_hdr);};

    //let dev_map_ptr = unsafe { &mut DEVMAP as *mut _ as *mut c_void };
    //let key = u64::from_be_bytes([outer_eth_hdr.dst_addr[0], outer_eth_hdr.dst_addr[1], outer_eth_hdr.dst_addr[2], outer_eth_hdr.dst_addr[3], outer_eth_hdr.dst_addr[4], outer_eth_hdr.dst_addr[5], 0,0]);
    //let res = unsafe{ bpf_redirect_map(dev_map_ptr, key, 0)};

    let eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    let src_mac = unsafe { (*eth_hdr_ptr).src_addr };
    let src_mac_le = u64::from_be_bytes([src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0,0]);
    info!( &ctx, "src_mac: {:x}", src_mac_le);
    let dst_mac = unsafe { (*eth_hdr_ptr).dst_addr };
    let dst_mac_le = u64::from_be_bytes([dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 0,0]);
    info!( &ctx, "dst_mac: {:x}", dst_mac_le);
    let ether_type = unsafe { (*eth_hdr_ptr).ether_type };
    match ether_type{
        EtherType::Ipv4 => info!(&ctx, "ether_type: ipv4"),
        _ => info!(&ctx, "ether_type: {}", ether_type as u16),
    }

    let ip_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let src_ip = u32::from_be(unsafe { (*ip_hdr_ptr).src_addr });
    info!( &ctx, "src_ip: {:i}", src_ip);
    let dst_ip = u32::from_be(unsafe { (*ip_hdr_ptr).dst_addr });
    info!( &ctx, "dst_ip: {:i}", dst_ip);
    let ip_proto = unsafe { (*ip_hdr_ptr).proto };
    match ip_proto{
        IpProto::Tcp => info!(&ctx, "ip_proto: tcp"),
        IpProto::Udp => info!(&ctx, "ip_proto: udp"),
        IpProto::Icmp => info!(&ctx, "ip_proto: icmp"),
        _ => info!(&ctx, "ip_proto: {}", ip_proto as u8),
    }

    



    let res = unsafe { bpf_redirect(phy_ifidx, 0) };
    info!(&ctx, "redirect res: {} to {}", res, phy_ifidx);
    Ok(xdp_action::XDP_REDIRECT)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
fn mask(ip: u32, cidr_length: u8) -> u32 {
    if cidr_length >= 32 {
        return ip; // No need to mask if CIDR length is 32 or greater
    }

    let mask: u32 = 0xFFFFFFFFu32.wrapping_shl(32 - u32::from(cidr_length));
    ip & mask
}

#[inline(always)]
fn uninit<T>() -> *mut T {
    let mut v: MaybeUninit<T> = MaybeUninit::uninit();
    v.as_mut_ptr() as *mut T
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}
