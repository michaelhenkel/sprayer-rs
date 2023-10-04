#![no_std]
#![no_main]

use core::mem::{self, zeroed, size_of};

use aya_bpf::{
    bindings::{xdp_action, bpf_fib_lookup as fib_lookup},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_redirect, bpf_fib_lookup, bpf_csum_diff, bpf_xdp_adjust_tail},
    programs::XdpContext,
    maps::HashMap, cty::c_void,
};
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto, self},
    udp::UdpHdr,
};
use common::{
    Interface,
    FlowKey,
    FlowNextHop,
    SrcDst,
    BthHdr,
    XskMap,
    SprayerHdr,
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

#[map(name = "EGRESSXSKMAP")]
static mut XSKMAP: XskMap<u32, u32> =
    XskMap::<u32, u32>::with_max_entries(64, 0);

#[map(name = "CURRENTQPID")]
static mut CURRENTQPID: HashMap<[u8;3], [u8;3]> =
    HashMap::<[u8;3], [u8;3]>::with_max_entries(2048, 0);

#[xdp]
pub fn xdp_encap(ctx: XdpContext) -> u32 {
    ////info!(&ctx, "xdp_encap");
    let intf = match unsafe { DECAPINTERFACE.get(&0) } {
        Some(intf) => {
            intf
        }
        None => {
            //info!(&ctx, "decap intf not found");
            return xdp_action::XDP_ABORTED
        }
    };

    let links = match unsafe { LINKS.get(&0) } {
        Some(links) => {
            links
        }
        None => {
            //info!(&ctx, "links not found");
            return xdp_action::XDP_ABORTED
        }
    };

    match try_xdp_encap(ctx, *intf, *links) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_encap(ctx: XdpContext, decap_intf: Interface, links: u8) -> Result<u32, u32> {
    info!(&ctx, "encap packet");
    let eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    if unsafe{ (*eth_hdr_ptr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ipv4_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ipv4_hdr_ptr).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }
    let udp_hdr_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    if u16::from_be(unsafe { (*udp_hdr_ptr).dest } ) != 4791 {
        info!(&ctx,"no rocev2");
        return Ok(xdp_action::XDP_PASS);
    }

    let bth_hdr_ptr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;

    let mut eth_hdr = unsafe { eth_hdr_ptr.read() };
    let mut ipv4_hdr = unsafe { ipv4_hdr_ptr.read() };
    let mut udp_hdr = unsafe { udp_hdr_ptr.read() };
    let bth_hdr = unsafe { bth_hdr_ptr.read() };

    let flow_next_hop = if let Some(flow_next_hop) = get_v4_next_hop_from_flow_table(&ctx){
        flow_next_hop
    } else if let Some(flow_next_hop) = get_next_hop(&ctx) {
        flow_next_hop
    } else {
        info!(&ctx,"no next hop found");
        return Ok(xdp_action::XDP_PASS);
    };

    let new_ipv4_tot_len = u16::from_be(ipv4_hdr.tot_len) + SprayerHdr::LEN as u16;
    ipv4_hdr.tot_len = u16::to_be(new_ipv4_tot_len);
    ipv4_hdr.check = 0;
    ipv4_hdr.check = csum(&ipv4_hdr.clone() as *const Ipv4Hdr as *mut u32, Ipv4Hdr::LEN as u32, 0);
    eth_hdr.src_addr = flow_next_hop.src_mac;
    eth_hdr.dst_addr = flow_next_hop.dst_mac;
    
    let psn_seq = bth_hdr.psn_seq;
    let qp_id = bth_hdr.dest_qpn;
    let op_code = u8::from_be(bth_hdr.opcode);
    let new_udp_src_port = u16::from(psn_seq[1]) << 8 | u16::from(psn_seq[2]);

    let first = if op_code == 0 {
        if let Err(e) = unsafe { CURRENTQPID.insert(&qp_id, &psn_seq, 0) }{
            warn!(&ctx, "currentqpid insert failed {}",e);
        }
        Some(&psn_seq)
    } else if op_code == 1 || op_code == 2 {
        let first = unsafe { CURRENTQPID.get(&qp_id) };
        if op_code == 2 {
            if let Err(e) = unsafe { CURRENTQPID.remove(&qp_id) }{
                warn!(&ctx, "currentqpid remove failed {}",e);
            }  
        }
        first.clone()
    } else {
        info!(&ctx, "unknown opcode");
        None
    };
    if let Some(first) = first {
        info!(&ctx,"new qp_id found");
        let sprayer_hdr = SprayerHdr{
            src_port: udp_hdr.source,
            padding: 0,
            first: *first,
        };
        let udp_len =u16::from_be(udp_hdr.len) as usize;
        udp_hdr.dest = u16::to_be(3000);
        udp_hdr.source = u16::to_be(hash_16bit(new_udp_src_port));
        udp_hdr.len = u16::to_be((udp_len + SprayerHdr::LEN) as u16);
        udp_hdr.check = 0;

        unsafe {
            bpf_xdp_adjust_head(ctx.ctx, -(SprayerHdr::LEN as i32));
        }
        
        let eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
        unsafe { eth_hdr_ptr.write(eth_hdr) };
        let ipv4_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
        unsafe { ipv4_hdr_ptr.write(ipv4_hdr) };
        let udp_hdr_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
        unsafe { udp_hdr_ptr.write(udp_hdr) };
        let sprayer_hdr_ptr = ptr_at_mut::<SprayerHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
        unsafe { sprayer_hdr_ptr.write(sprayer_hdr) };
        let bth_hdr_ptr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + SprayerHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
        unsafe { bth_hdr_ptr.write(bth_hdr) };
    }

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
            //info!(ctx, "flow_next_hop not found");
            return None;
        }
    }
}

#[inline(always)]
fn get_next_hop(ctx: &XdpContext) -> Option<FlowNextHop>{
    let ip_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let ipv4_src_dst_port_ptr = ptr_at::<SrcDst>(&ctx, EthHdr::LEN + 12)?;
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

