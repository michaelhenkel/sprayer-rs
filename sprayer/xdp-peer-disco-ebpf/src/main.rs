#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{xdp_action, bpf_fib_lookup as fib_lookup},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_fib_lookup, bpf_redirect},
    programs::XdpContext,
    maps::HashMap, cty::c_void,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,

};
use core::mem::{self, MaybeUninit};
use core::mem::{size_of, zeroed};

use common::{Interface, FlowKey, FlowNextHop, SrcDst, XskMap, Stats};


#[map(name = "FLOWTABLE")]
static mut FLOWTABLE: HashMap<FlowKey, FlowNextHop> =
    HashMap::<FlowKey, FlowNextHop>::with_max_entries(256, 0);

#[map(name = "INGRESSXSKMAP")]
static mut XSKMAP: XskMap<u32, u32> =
    XskMap::<u32, u32>::with_max_entries(64, 0);

#[map(name = "STATSMAP")]
static mut STATSMAP: HashMap<u32, Stats> =
    HashMap::<u32, Stats>::with_max_entries(2048, 0);

#[xdp]
pub fn xdp_peer_disco(ctx: XdpContext) -> u32 {
    match try_xdp_peer_disco(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}



fn try_xdp_peer_disco(ctx: XdpContext) -> Result<u32, u32> {
    ////info!(&ctx, "xdp_dummy");
    
    let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {},
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }
    let ipv4_hdr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    match  unsafe { (*ipv4_hdr).proto } {
        IpProto::Udp => {},
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }
    let udp_hdr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;

    match unsafe { (*udp_hdr).dest }{
        4791 => {
            if let Some(stats) = unsafe { STATSMAP.get_ptr_mut(&0)} {
                unsafe { (*stats).tx += 1};
                return Ok(xdp_action::XDP_DROP)
            }
        },
        4792 => {
            unsafe { STATSMAP.insert(&0, &Stats { tx: 0 }, 0)}.map_err(|_| xdp_action::XDP_ABORTED)?;
        },
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    Ok(xdp_action::XDP_DROP)
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
            //info!(ctx, "flow_next_hop not found");
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
        //info!(ctx,"fib lookup failed for dst ip {:i}, ifidx {}, ret {}",dst_ip, if_idx, ret);
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

#[inline(always)]
fn mac_to_int(mac: [u8;6]) -> u64 {
    let mut mac_dec: u64 = 0;
    for i in 0..6 {
        mac_dec = mac_dec << 8;
        mac_dec = mac_dec | mac[i] as u64;
    }
    mac_dec
}
