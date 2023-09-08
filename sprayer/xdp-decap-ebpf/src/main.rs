#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{xdp_action, self},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_fib_lookup, bpf_redirect},
    programs::XdpContext,
    cty::c_void,
    maps::HashMap,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use core::mem::{self, zeroed, size_of};

#[map(name = "DEVMAP")]
static mut DEVMAP: HashMap<[u8;6], u32> =
    HashMap::<[u8;6], u32>::with_max_entries(10, 0);

#[xdp]
pub fn xdp_decap(ctx: XdpContext) -> u32 {
    match try_xdp_decap(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_decap(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "xdp_decap");
    let eth = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    if unsafe{ (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ip).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }
    let udp = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let res = if unsafe { u16::from_be((*udp).dest) } == 3000 {
        unsafe { bpf_xdp_adjust_head(ctx.ctx, (EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as i32)};
        let inner_eth = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
        if unsafe{ (*inner_eth).ether_type } != EtherType::Ipv4 {
            return Ok(xdp_action::XDP_PASS);
        }
        let inner_ip = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
        let dst_ip = unsafe { (*inner_ip).dst_addr };
        let if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
        
        let mut params: bindings::bpf_fib_lookup = unsafe { zeroed() };
        params.family = 2;
        params.ifindex = if_idx;
        params.__bindgen_anon_4.ipv4_dst = dst_ip;
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
        //let mut outer_eth_hdr = unsafe { inner_eth.read() };
        //outer_eth_hdr.dst_addr = params.dmac;
        //outer_eth_hdr.src_addr = params.smac;
        //unsafe { inner_eth.write(outer_eth_hdr);};
        unsafe { bpf_redirect(params.ifindex, 0) }

    } else {
        xdp_action::XDP_PASS.into()
    };
    info!(&ctx, "redirect res: {}", res);
    Ok(res as u32)
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