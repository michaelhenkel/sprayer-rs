#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{xdp_action, self},
    macros::xdp,
    helpers::{bpf_xdp_adjust_head, bpf_fib_lookup, bpf_redirect},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,

};
use core::mem::{self, MaybeUninit};
use core::mem::{size_of, zeroed};
use aya_bpf::cty::c_void;

#[xdp]
pub fn xdp_dummy(ctx: XdpContext) -> u32 {
    match try_xdp_dummy(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_dummy(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "xdp_dummy");
    let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    let ip_hdr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let udp_hdr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let src_mac = unsafe { mac_to_int((*eth_hdr).src_addr) };
    let dst_mac = unsafe { mac_to_int((*eth_hdr).dst_addr) };
    let src_ip = unsafe { u32::from_be((*ip_hdr).src_addr) };
    let dst_ip = unsafe { u32::from_be((*ip_hdr).dst_addr) };
    let src_port = unsafe { u16::from_be((*udp_hdr).source) };
    let dst_port = unsafe { u16::from_be((*udp_hdr).dest) };
    info!(&ctx,"src_mac: {:x}, dst_mac: {:x}, src_ip: {:i}, dst_ip: {:i}, src_port: {}, dst_port: {}", src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port);
    Ok(xdp_action::XDP_PASS)
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
