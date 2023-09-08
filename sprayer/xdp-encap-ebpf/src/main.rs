#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{xdp_action, self},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_fib_lookup, bpf_redirect, bpf_redirect_map},
    programs::XdpContext,
    maps::HashMap,
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

#[map(name = "PHYINTF")]
static mut PHYINTF: HashMap<u8, u32> =
    HashMap::<u8, u32>::with_max_entries(1, 0);

#[map(name = "DEVMAP")]
static mut DEVMAP: HashMap<[u8;6], u32> =
    HashMap::<[u8;6], u32>::with_max_entries(10, 0);

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

    let outer_eth_hdr = unsafe { eth_hdr.read() };

    let (hdr_len, payload_len, ifidx) = match unsafe{ (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {
            let ip_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
            
            let ip_proto = unsafe { (*ip_hdr_ptr).proto };
            match ip_proto {
                IpProto::Tcp => {},
                IpProto::Udp => {},
                _ => {
                    let ipp = ip_proto as u8;
                    info!(&ctx,"ip_proto not tcp or udp, {} passing", ipp);
                    return Ok(xdp_action::XDP_PASS)
                }
            }
            let dst_ip = unsafe { (*ip_hdr_ptr).dst_addr };
            let if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
            
            let mut outer_ip_hdr = unsafe { ip_hdr_ptr.read() };
            let new_ip_hdr_tot_len = u16::from_be(outer_ip_hdr.tot_len) + (EthHdr::LEN  + Ipv4Hdr::LEN + UdpHdr::LEN) as u16;
            outer_ip_hdr.tot_len = u16::to_be(new_ip_hdr_tot_len);
            outer_ip_hdr.proto = IpProto::Udp;
            unsafe {
                bpf_xdp_adjust_head(ctx.ctx, -((EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as i32));
            }
            let outer_ip_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
            unsafe { 
                outer_ip_ptr.write(outer_ip_hdr);
            };
  

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
            info!(&ctx, "ret: {}", ret);
            info!(&ctx, "dmac: {}:{}:{}:{}:{}:{}", params.dmac[0],params.dmac[1],params.dmac[2],params.dmac[3],params.dmac[4],params.dmac[5]);
            info!(&ctx, "smac: {}:{}:{}:{}:{}:{}", params.smac[0],params.smac[1],params.smac[2],params.smac[3],params.smac[4],params.smac[5]);

            info!(&ctx, "dst: {:i}", unsafe { params.__bindgen_anon_4.ipv4_dst });
            info!(&ctx, "src: {:i}", unsafe { params.__bindgen_anon_3.ipv4_src });
            info!(&ctx, "orig ifidx: {}", if_idx);
            info!(&ctx, "ifidx: {}", params.ifindex );

            //outer_eth_hdr.src_addr = params.smac;
            //outer_eth_hdr.dst_addr = params.dmac;
            let eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
            unsafe { eth_hdr_ptr.write(outer_eth_hdr);};
    
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

    let dev_map_ptr = unsafe { &mut DEVMAP as *mut _ as *mut c_void };
    let key = u64::from_be_bytes([outer_eth_hdr.dst_addr[0], outer_eth_hdr.dst_addr[1], outer_eth_hdr.dst_addr[2], outer_eth_hdr.dst_addr[3], outer_eth_hdr.dst_addr[4], outer_eth_hdr.dst_addr[5], 0,0]);
    let res = unsafe{ bpf_redirect_map(dev_map_ptr, key, 0)};

    //let res = unsafe { bpf_redirect(ifidx, 0) };
    info!(&ctx, "redirect res: {}", res);
    Ok(xdp_action::XDP_REDIRECT)
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
