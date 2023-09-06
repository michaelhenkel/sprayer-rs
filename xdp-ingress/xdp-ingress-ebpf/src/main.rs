#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    helpers::bpf_xdp_adjust_head,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use core::mem;

#[xdp]
pub fn xdp_ingress(ctx: XdpContext) -> u32 {
    match try_xdp_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_ingress(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    //let new_ctx = XdpContext::new(ctx.ctx);
    //unsafe { (*ctx.ctx).data = * };
    let eth = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    
    if unsafe{ (*eth).ether_type } != EtherType::Ipv4 {
        info!(&ctx,"not an IP packet");
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    
    if unsafe { (*ip).proto } != IpProto::Udp {
        info!(&ctx,"not an UDP packet");
        return Ok(xdp_action::XDP_PASS);
    }
    
    info!(&ctx, "received a UDP packet");

    let udp = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    
    let destination_port = unsafe { u16::from_be((*udp).dest) };
    
    if destination_port == 3000 {
        info!(&ctx, "received UDP on port 3000");
        unsafe { bpf_xdp_adjust_head(ctx.ctx, (EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as i32)};
    }
    info!(&ctx, "received a packet");

    Ok(xdp_action::XDP_PASS)
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
