#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{xdp_action, self},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_fib_lookup, bpf_redirect},
    programs::{XdpContext, tc},
    maps::HashMap,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto, self},
    udp::UdpHdr, tcp::TcpHdr,
};
use core::mem::{self, MaybeUninit};
use core::mem::{size_of, zeroed};
use aya_bpf::cty::c_void;
use common::{NetworkKey, Interface, FlowKey, FlowNextHop};

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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SrcDst{
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

impl SrcDst {
    pub const LEN: usize = mem::size_of::<SrcDst>();
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

#[map(name = "INTERFACE")]
static mut INTERFACE: HashMap<u32, Interface> =
    HashMap::<u32, Interface>::with_max_entries(256, 0);

#[map(name = "FLOWTABLE")]
static mut FLOWTABLE: HashMap<FlowKey, FlowNextHop> =
    HashMap::<FlowKey, FlowNextHop>::with_max_entries(256, 0);

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
    let flow_next_hop = match get_v4_next_hop_from_flow_table(&ctx) {
        Some(fnh) => {
            info!( &ctx, "flow found");
            fnh
        }
        None => {
            match get_next_hop(&ctx, phy_intf){
                Some(fnh_or_result) => {
                    match fnh_or_result {
                        FnhOrResult::Fnh(fnh) => {
                            fnh
                        }
                        FnhOrResult::Result(res) => {
                            return res;
                        }
                    }
                }
                None => {
                    info!(&ctx, "flow_next_hop not found");
                    return Ok(xdp_action::XDP_PASS);
                }
            }
        }
    };

    let res = write_outer_hdr(&ctx, flow_next_hop);
    
    
    
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

    res
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

enum FnhOrResult{
    Fnh(FlowNextHop),
    Result(Result<u32,u32>),
}

#[inline(always)]
fn get_v4_next_hop_from_flow_table(ctx: &XdpContext) -> Option<FlowNextHop>{
    
    let ipv4_proto_ptr = ptr_at::<u8>(&ctx, EthHdr::LEN + 9)?;
    let ipv4_src_dst_port_ptr = ptr_at::<SrcDst>(&ctx, EthHdr::LEN + 12)?;

    let mut flow_key: FlowKey = unsafe { zeroed() };

    flow_key.dst_ip = unsafe { (*ipv4_src_dst_port_ptr).dst_ip };
    flow_key.src_ip = unsafe { (*ipv4_src_dst_port_ptr).src_ip };
    flow_key.dst_port = unsafe { (*ipv4_src_dst_port_ptr).dst_port };
    flow_key.src_port = unsafe { (*ipv4_src_dst_port_ptr).src_port };
    flow_key.ip_proto = unsafe { *ipv4_proto_ptr };

    let x = unsafe { FLOWTABLE.get(&flow_key) };

    match unsafe { FLOWTABLE.get(&flow_key) } {
        Some(fnh) => {
            return Some(fnh.clone())
        }
        None => {
            info!(ctx, "flow_next_hop not found");
            return None;
        }
    }

    
}

#[inline(always)]
fn get_next_hop(ctx: &XdpContext, phy_intf: u32) -> Option<FnhOrResult> {
    
    let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0)?;

    let mut outer_eth_hdr = unsafe { eth_hdr.read() };

    match unsafe{ (*eth_hdr).ether_type } {
        EtherType::Arp => {
            info!(ctx, "arp");
            let arp_hdr = ptr_at_mut::<ArpHdr>(&ctx, EthHdr::LEN)?;
            let oper = u16::from_be(unsafe{ (*arp_hdr).oper });
            if oper == 1 {
                info!(ctx, "arp request");                
                let dst_addr = u32::from_be(unsafe{ (*arp_hdr).tpa });
                let src_addr = u32::from_be(unsafe{ (*arp_hdr).spa });
                let src_mac = unsafe { (*arp_hdr).sha };
                let intf = match unsafe { INTERFACE.get(&dst_addr) } {
                    Some(intf) => intf,
                    None => {
                        info!(ctx, "intf not found");
                        return Some(FnhOrResult::Result(Ok(xdp_action::XDP_DROP)));
                    }
                };
                let pm = intf.mac;
                outer_eth_hdr.src_addr = pm;
                outer_eth_hdr.dst_addr = src_mac;
                unsafe { (*arp_hdr).oper = u16::from_be(2) };
                unsafe { (*arp_hdr).spa = u32::from_be(dst_addr)}
                unsafe { (*arp_hdr).tpa = u32::from_be(src_addr)}
                unsafe { (*arp_hdr).tha = src_mac};
                unsafe { (*arp_hdr).sha = pm};
                unsafe { eth_hdr.write(outer_eth_hdr);};
                info!(ctx, "replying");
                return Some(FnhOrResult::Result(Ok(xdp_action::XDP_TX)));
            }
            return Some(FnhOrResult::Result(Ok(xdp_action::XDP_PASS)));
        },
        EtherType::Ipv4 => {
            let ip_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
            let ip_proto = unsafe { (*ip_hdr_ptr).proto };
            let src_dst_port = match ip_proto {
                IpProto::Tcp => {
                    let tcp_hdr_ptr = ptr_at_mut::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    let src_port = unsafe { (*tcp_hdr_ptr).source };
                    let dst_port = unsafe { (*tcp_hdr_ptr).dest };
                    Some((src_port, dst_port))
                },
                IpProto::Udp => {
                    let udp_hdr_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    let src_port = unsafe { (*udp_hdr_ptr).source };
                    let dst_port = unsafe { (*udp_hdr_ptr).dest };
                    Some((src_port, dst_port))
                },
                IpProto::Icmp => None,
                _ => {
                    let ipp = ip_proto as u8;
                    info!(ctx,"ip_proto not tcp or udp, {} passing", ipp);
                    return Some(FnhOrResult::Result(Ok(xdp_action::XDP_PASS)));
                }
            };
            let dst_ip = unsafe { (*ip_hdr_ptr).dst_addr };
            let if_idx = unsafe { (*ctx.ctx).ingress_ifindex };

            let nh = match unsafe { INTERFACE.get(&u32::from_be(dst_ip)) } {
                Some(nh) => {
                    nh.next_hop.clone()
                }
                None => {
                    info!(ctx, "nh not found");
                    return Some(FnhOrResult::Result(Ok(xdp_action::XDP_ABORTED)));
                }
            };
            info!(ctx, "nh: {}", nh);
            let phy_ip = match unsafe { PHYIP.get(&0) } {
                Some(phy_ip) => {
                    phy_ip.clone()
                }
                None => {
                    info!(ctx, "phy_ip");
                    return Some(FnhOrResult::Result(Ok(xdp_action::XDP_ABORTED)));
                }
            };
            info!(ctx, "phy_ip: {}", phy_ip);
            let mut params: bindings::bpf_fib_lookup = unsafe { zeroed() };
            params.family = 2;
            params.ifindex = phy_intf;
            params.__bindgen_anon_4.ipv4_dst = u32::from_be(nh);
            let params_ptr: *mut bindings::bpf_fib_lookup = &mut params as *mut _;

            let param_size = size_of::<bindings::bpf_fib_lookup>();
            info!(ctx, "param_size: {}", param_size);
        
            let ctx_ptr = ctx.ctx as *mut _ as *mut c_void;
            let ret: i64 = unsafe {
                bpf_fib_lookup(ctx_ptr, params_ptr, 64, 0)
            };
            if ret != 0 {
                info!(ctx,"fib lookup failed for dst ip {:i}, ifidx {}, ret {}",dst_ip, if_idx, ret);
                return Some(FnhOrResult::Result(Ok(xdp_action::XDP_ABORTED)));
            }
            let flow_next_hop = FlowNextHop{
                dst_ip: unsafe { params.__bindgen_anon_4.ipv4_dst },
                src_ip: unsafe { params.__bindgen_anon_3.ipv4_src },
                dst_mac: params.dmac,
                src_mac: params.smac,
                ifidx: params.ifindex,
            };

            if let Some((src_port, dst_port)) = src_dst_port {
                let mut flow_key: FlowKey = unsafe { zeroed() };
                flow_key.dst_ip = unsafe { (*ip_hdr_ptr).dst_addr };
                flow_key.src_ip = unsafe { (*ip_hdr_ptr).src_addr };
                flow_key.dst_port = dst_port;
                flow_key.src_port = src_port;
                flow_key.ip_proto = unsafe { (*ip_hdr_ptr).proto as u8 };
                unsafe { FLOWTABLE.insert(&flow_key, &flow_next_hop, 0) };
            }

            return Some(FnhOrResult::Fnh(flow_next_hop));
        },
        _ => {
            return Some(FnhOrResult::Result(Ok(xdp_action::XDP_PASS)));
        },
    };
    
    return None
}

#[inline(always)]
fn write_outer_hdr(ctx: &XdpContext, flow_next_hop: FlowNextHop) -> Result<u32,u32> {
    let new_eth_hdr = EthHdr{
        dst_addr: flow_next_hop.dst_mac,
        src_addr: flow_next_hop.src_mac,
        ether_type: EtherType::Ipv4,
    };
    let ip_hdr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_DROP)?;
    let new_ip_hdr_tot_len = u16::from_be( unsafe { (*ip_hdr).tot_len }+ (EthHdr::LEN  + Ipv4Hdr::LEN + UdpHdr::LEN) as u16);
    let new_udp_hdr_len = new_ip_hdr_tot_len - Ipv4Hdr::LEN as u16;
    let new_ip_header = Ipv4Hdr{
        _bitfield_1: unsafe { (*ip_hdr)._bitfield_1 },
        _bitfield_align_1: unsafe{ (*ip_hdr)._bitfield_align_1 },
        tos: unsafe { (*ip_hdr).tos },
        frag_off: unsafe { (*ip_hdr).frag_off },
        tot_len: u16::to_be(new_ip_hdr_tot_len),
        id: unsafe { (*ip_hdr).id },
        ttl: unsafe { (*ip_hdr).ttl },
        proto: IpProto::Udp,
        check: unsafe{ (*ip_hdr).check },
        src_addr: flow_next_hop.src_ip,
        dst_addr: flow_next_hop.dst_ip,
    };
    let new_udp_header = UdpHdr{
        source: u16::to_be(1000),
        dest: u16::to_be(3000),
        len: u16::to_be(new_udp_hdr_len),
        check: 0,
    };

    unsafe {
        bpf_xdp_adjust_head(ctx.ctx, -((EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as i32));
    }

    let outer_eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_DROP)?;
    unsafe { outer_eth_hdr_ptr.write(new_eth_hdr) };
    let outer_ip_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_DROP)?;
    unsafe { outer_ip_ptr.write(new_ip_header); };
    let outer_udp_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_DROP)?;
    unsafe { outer_udp_ptr.write(new_udp_header); };

    let res = unsafe { bpf_redirect(flow_next_hop.ifidx, 0) };

    Ok(res as u32)

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

