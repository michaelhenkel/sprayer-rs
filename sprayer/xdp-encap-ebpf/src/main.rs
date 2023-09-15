#![no_std]
#![no_main]

use core::mem::{self, zeroed, size_of};

use aya_bpf::{
    bindings::{xdp_action, bpf_fib_lookup as fib_lookup},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_redirect, bpf_fib_lookup},
    programs::XdpContext,
    maps::HashMap, cty::c_void,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use common::{Interface, FlowKey, FlowNextHop};

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SrcDst{
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

#[map(name = "DECAPINTERFACE")]
static mut DECAPINTERFACE: HashMap<u32, Interface> =
    HashMap::<u32, Interface>::with_max_entries(1, 0);

#[map(name = "FLOWTABLE")]
static mut FLOWTABLE: HashMap<FlowKey, FlowNextHop> =
    HashMap::<FlowKey, FlowNextHop>::with_max_entries(256, 0);

#[xdp]
pub fn xdp_encap(ctx: XdpContext) -> u32 {
    info!(&ctx, "xdp_encap");
    let intf = match unsafe { DECAPINTERFACE.get(&0) } {
        Some(intf) => {
            intf
        }
        None => {
            info!(&ctx, "decap intf not found");
            return xdp_action::XDP_ABORTED
        }
    };
    match try_xdp_encap(ctx, *intf) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_encap(ctx: XdpContext, decap_intf: Interface) -> Result<u32, u32> {
    info!(&ctx, "encap packet");
    let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {},
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }
    let ipv4_hdr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    match  unsafe { (*ipv4_hdr).proto } {
        IpProto::Tcp => {},
        IpProto::Udp => {},
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }

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
    let outer_ip_hdr = Ipv4Hdr{
        _bitfield_1: unsafe { (*ipv4_hdr)._bitfield_1 },
        _bitfield_align_1: unsafe{ (*ipv4_hdr)._bitfield_align_1 },
        tos: unsafe { (*ipv4_hdr).tos },
        frag_off: unsafe { (*ipv4_hdr).frag_off },
        tot_len: u16::to_be(outer_ip_hdr_len),
        id: unsafe { (*ipv4_hdr).id },
        ttl: unsafe { (*ipv4_hdr).ttl },
        proto: IpProto::Udp,
        check: unsafe{ (*ipv4_hdr).check },
        src_addr: unsafe { (*ipv4_hdr).src_addr },
        dst_addr: unsafe { (*ipv4_hdr).dst_addr },
    };
    let outer_udp_hdr_len = outer_ip_hdr_len - Ipv4Hdr::LEN as u16;
    let outer_udp_hdr = UdpHdr{
        source: u16::to_be(1000),
        dest: u16::to_be(3000),
        len: u16::to_be(outer_udp_hdr_len),
        check: 0,
    };

    let src_mac = mac_to_int(outer_eth_hdr.src_addr);
    let dst_mac = mac_to_int(outer_eth_hdr.dst_addr);
    let src_ip = u32::from_be(outer_ip_hdr.src_addr);
    let dst_ip = u32::from_be(outer_ip_hdr.dst_addr);
    let src_port = u16::from_be(outer_udp_hdr.source);
    let dst_port = u16::from_be(outer_udp_hdr.dest);
    info!(&ctx, "src_mac: {:x}, dst_mac: {:x}, src_ip: {:i}, dst_ip: {:i}, src_port: {}, dst_port: {}", src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port);

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
    info!(&ctx, "redirect res: {}", res);
    Ok(res as u32)
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

