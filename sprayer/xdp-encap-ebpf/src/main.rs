#![no_std]
#![no_main]

use core::mem::{self, zeroed, size_of};

use aya_bpf::{
    bindings::{xdp_action, bpf_fib_lookup as fib_lookup},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_redirect, bpf_fib_lookup, bpf_csum_diff},
    programs::XdpContext,
    maps::HashMap, cty::c_void,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use common::{
    Interface,
    FlowKey,
    FlowNextHop,
    SrcDst,
    BthHdr,
    XskMap,
};

#[map(name = "LINKS")]
static mut LINKS: HashMap<u8, u8> =
    HashMap::<u8, u8>::with_max_entries(1, 0);

#[map(name = "COUNTER")]
static mut COUNTER: HashMap<u8, u8> =
    HashMap::<u8, u8>::with_max_entries(1, 0);

#[map(name = "DECAPINTERFACE")]
static mut DECAPINTERFACE: HashMap<u32, Interface> =
    HashMap::<u32, Interface>::with_max_entries(1, 0);

#[map(name = "FLOWTABLE")]
static mut FLOWTABLE: HashMap<FlowKey, FlowNextHop> =
    HashMap::<FlowKey, FlowNextHop>::with_max_entries(256, 0);

#[xdp]
pub fn xdp_encap(ctx: XdpContext) -> u32 {
    //info!(&ctx, "xdp_encap");
    let intf = match unsafe { DECAPINTERFACE.get(&0) } {
        Some(intf) => {
            intf
        }
        None => {
            info!(&ctx, "decap intf not found");
            return xdp_action::XDP_ABORTED
        }
    };

    let links = match unsafe { LINKS.get(&0) } {
        Some(links) => {
            links
        }
        None => {
            info!(&ctx, "links not found");
            return xdp_action::XDP_ABORTED
        }
    };

    match try_xdp_encap(ctx, *intf, *links) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_encap(ctx: XdpContext, decap_intf: Interface, links: u8) -> Result<u32, u32> {
    //info!(&ctx, "encap packet");
    let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {},
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }
    let ipv4_hdr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let psn_seq = match  unsafe { (*ipv4_hdr).proto } {
        IpProto::Udp => {
            let udp_hdr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
            if unsafe { u16::from_be((*udp_hdr).dest) } == 4791 {
                let bth_hdr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
                unsafe { (*bth_hdr).psn_seq }
            } else {
                [1,2,3]
                //return Ok(xdp_action::XDP_PASS);
            }
        },
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let udp_src_port = u16::from(psn_seq[1]) << 8 | u16::from(psn_seq[2]);

    let flow_next_hop = if let Some(flow_next_hop) = get_v4_next_hop_from_flow_table(&ctx){
        flow_next_hop
    } else if let Some(flow_next_hop) = get_next_hop(&ctx) {
        flow_next_hop
    } else {
        return Ok(xdp_action::XDP_PASS);
    };


    let outer_eth_hdr = EthHdr{
        dst_addr: flow_next_hop.dst_mac,
        src_addr: flow_next_hop.src_mac,
        ether_type: EtherType::Ipv4,
    };
    
    let outer_ip_hdr_len = u16::from_be( unsafe { (*ipv4_hdr).tot_len }) + (EthHdr::LEN  + Ipv4Hdr::LEN + UdpHdr::LEN) as u16;
    
    let ttl = unsafe { (*ipv4_hdr).ttl - 1};
    let bitfield_1 = unsafe { (*ipv4_hdr)._bitfield_1 };
    let bitfield_align_1 = unsafe { (*ipv4_hdr)._bitfield_align_1 };
    let tos = unsafe { (*ipv4_hdr).tos };
    let frag_off = unsafe { (*ipv4_hdr).frag_off };
    let id = unsafe { (*ipv4_hdr).id };
    let src_addr = unsafe { (*ipv4_hdr).src_addr };
    let dst_addr = unsafe { (*ipv4_hdr).dst_addr };
    

    let mut outer_ip_hdr = unsafe { zeroed::<Ipv4Hdr>()};
    outer_ip_hdr._bitfield_1 = bitfield_1;
    outer_ip_hdr._bitfield_align_1 = bitfield_align_1;
    outer_ip_hdr.tos = tos;
    outer_ip_hdr.frag_off = frag_off;
    outer_ip_hdr.tot_len = u16::to_be(outer_ip_hdr_len);
    outer_ip_hdr.id = id;
    outer_ip_hdr.ttl = ttl;
    outer_ip_hdr.proto = IpProto::Udp;
    outer_ip_hdr.check = 0;
    outer_ip_hdr.src_addr = src_addr;
    outer_ip_hdr.dst_addr = dst_addr;
    
    let ip_csum = csum(&outer_ip_hdr.clone() as *const Ipv4Hdr as *mut u32, Ipv4Hdr::LEN as u32, 0);
    outer_ip_hdr.check = ip_csum;

    /*
    let counter = match unsafe { COUNTER.get_ptr_mut(&0) } {
        Some(counter) => {
            counter
        }
        None => {
            info!(&ctx, "counter");
            return Ok(xdp_action::XDP_ABORTED)
        }
    };

    let mut current_counter = unsafe { *counter };
    let src_port_counter = if current_counter > 0 {
        current_counter+2
    } else {
        0
    };
    let src_port = 1000 + src_port_counter as u16;
    */

    let outer_udp_hdr_len = outer_ip_hdr_len - Ipv4Hdr::LEN as u16;
    let outer_udp_hdr = UdpHdr{
        source: hash_16bit(udp_src_port),
        dest: u16::to_be(3001),
        len: u16::to_be(outer_udp_hdr_len),
        check: 0,
    };

    /*
    current_counter = if current_counter == links - 1{
        0
    } else {
        current_counter + 1
    };

    unsafe { *counter = current_counter };
    */
    unsafe {
        bpf_xdp_adjust_head(ctx.ctx, -((EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as i32));
    }

    let outer_eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_DROP)?;
    unsafe { outer_eth_hdr_ptr.write(outer_eth_hdr) };
    let outer_ip_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_DROP)?;
    unsafe { outer_ip_ptr.write(outer_ip_hdr); };
    let outer_udp_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_DROP)?;
    unsafe { outer_udp_ptr.write(outer_udp_hdr); };

    let res = unsafe { bpf_redirect(decap_intf.ifidx, 0) };
    Ok(res as u32)
}

#[inline(always)]
fn hash_16bit(num: u16) -> u16 {
    let mut hash = num;
    hash = (hash ^ (hash >> 8)).wrapping_mul(0x00FF);
    hash = (hash ^ (hash >> 5)).wrapping_mul(0x5BD1);
    hash = hash ^ (hash >> 3);
    hash = hash ^ (hash >> 2);
    hash = hash ^ (hash >> 1);
    hash
}

#[inline(always)]
fn mac_to_int(mac: [u8;6]) -> u64 {
    let mut mac_dec: u64 = 0;
    for i in 0..6 {
        mac_dec = mac_dec << 8;
        mac_dec = mac_dec | mac[i] as u64;
    }
    mac_dec
}

#[inline(always)]
fn csum(data_start: *mut u32, data_size: u32, csum: u32) -> u16 {
    let cs = unsafe { bpf_csum_diff(0 as *mut u32, 0, data_start, data_size, csum) };
    csum_fold_helper(cs)
}

#[inline(always)]
fn csum_fold_helper(csum: i64) -> u16 {
    let mut sum = csum;
    for _ in 0..4 {
        if sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !sum as u16
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
fn get_next_hop(ctx: &XdpContext) -> Option<FlowNextHop>{
    let ip_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let ipv4_src_dst_port_ptr = ptr_at::<SrcDst>(&ctx, EthHdr::LEN + 12)?;
    let if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
    let dst_ip = unsafe { (*ip_hdr_ptr).dst_addr };
    let src_ip = unsafe { (*ip_hdr_ptr).src_addr };
    let mut params: fib_lookup = unsafe { zeroed() };
    params.family = 2;
    params.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    params.__bindgen_anon_4.ipv4_dst = dst_ip;
    let params_ptr: *mut fib_lookup = &mut params as *mut _;

    let _param_size = size_of::<fib_lookup>();        
    let ctx_ptr = ctx.ctx as *mut _ as *mut c_void;
    let ret: i64 = unsafe {
        bpf_fib_lookup(ctx_ptr, params_ptr, 64, 0)
    };
    if ret != 0 {
        info!(ctx,"fib lookup failed for dst ip {:i}, ifidx {}, ret {}",dst_ip, if_idx, ret);
        return None;
    }
    let flow_next_hop = FlowNextHop{
        dst_ip: unsafe { params.__bindgen_anon_4.ipv4_dst },
        src_ip: unsafe { params.__bindgen_anon_3.ipv4_src },
        dst_mac: params.dmac,
        src_mac: params.smac,
        ifidx: params.ifindex,
    };

    let mut flow_key: FlowKey = unsafe { zeroed() };
    flow_key.dst_ip = dst_ip;
    flow_key.src_ip = src_ip;
    flow_key.dst_port = unsafe { (*ipv4_src_dst_port_ptr).dst_port };
    flow_key.src_port = unsafe { (*ipv4_src_dst_port_ptr).src_port };
    flow_key.ip_proto = unsafe { (*ip_hdr_ptr).proto as u8 };
    if let Err(e) = unsafe { FLOWTABLE.insert(&flow_key, &flow_next_hop, 0) }{
        return None;
    }
    Some(flow_next_hop)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
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

