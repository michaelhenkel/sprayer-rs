#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_redirect},
    programs::XdpContext,
    maps::HashMap,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use common::Interface;

#[map(name = "ENCAPINTERFACE")]
static mut ENCAPINTERFACE: HashMap<u32, Interface> =
    HashMap::<u32, Interface>::with_max_entries(1, 0);

#[xdp]
pub fn xdp_decap(ctx: XdpContext) -> u32 {
    let intf = match unsafe { ENCAPINTERFACE.get(&0) } {
        Some(intf) => {
            intf
        }
        None => {
            info!(&ctx, "encap intf not found");
            return xdp_action::XDP_ABORTED
        }
    };
    match try_xdp_decap(ctx, *intf) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_decap(ctx: XdpContext, encap_intf: Interface) -> Result<u32, u32> {
    //info!(&ctx, "xdp_decap");
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
        unsafe { bpf_redirect(encap_intf.ifidx, 0) }

    } else {
        xdp_action::XDP_PASS.into()
    };
    //info!(&ctx, "redirect res: {}", res);
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
