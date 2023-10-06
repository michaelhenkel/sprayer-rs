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
use aya_log_ebpf::{info, warn};
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

#[map(name = "CURRENTFIRST")]
static mut CURRENTFIRST: HashMap<[u8;3], [u8;3]> =
    HashMap::<[u8;3], [u8;3]>::with_max_entries(2048, 0);

#[map(name = "PREVFIRST")]
static mut PREVFIRST: HashMap<[u8;3], [u8;3]> =
    HashMap::<[u8;3], [u8;3]>::with_max_entries(2048, 0);

#[map(name = "STARTSEQ")]
static mut STARTSEQ: HashMap<[u8;3], [u8;3]> =
    HashMap::<[u8;3], [u8;3]>::with_max_entries(2048, 0);

#[map(name = "ENDSEQ")]
static mut ENDSEQ: HashMap<[u8;3], [u8;3]> =
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
        return Ok(xdp_action::XDP_PASS);
    }
    let bth_hdr_ptr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;

    let flow_next_hop = if let Some(flow_next_hop) = get_v4_next_hop_from_flow_table(&ctx){
        flow_next_hop
    } else if let Some(flow_next_hop) = get_next_hop(&ctx) {
        flow_next_hop
    } else {
        return Ok(xdp_action::XDP_PASS);
    };

    let psn_seq_list = unsafe { (*bth_hdr_ptr).psn_seq };
    let psn_seq: u32 = u32::from_be_bytes([0, psn_seq_list[0], psn_seq_list[1], psn_seq_list[2]]);
    let dst_qp_list = unsafe { (*bth_hdr_ptr).dest_qpn };
    //let dst_qp: u32 = u32::from_be_bytes([0, dst_qp_list[0], dst_qp_list[1], dst_qp_list[2]]);
    let op_code = u8::from_be(unsafe { (*bth_hdr_ptr).opcode });
    let udp_src_port = u16::from_be(unsafe { (*udp_hdr_ptr).source });
    let new_udp_src_port = u16::from(psn_seq_list[1]) << 8 | u16::from(psn_seq_list[2]);
    let new_udp_src_port = hash_16bit(new_udp_src_port);
    let udp_len = u16::from_be(unsafe { (*udp_hdr_ptr).len } );
    let ipv4_tot_len = u16::from_be(unsafe { (*ipv4_hdr_ptr).tot_len } );


    if op_code == 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    let start_seq = if let Some(start_seq) = unsafe { STARTSEQ.get(&dst_qp_list) }{
        *start_seq
    } else if op_code == 0 {
        unsafe { STARTSEQ.insert(&dst_qp_list, &psn_seq_list, 0) }.map_err(|_| xdp_action::XDP_ABORTED)?;
        psn_seq_list
    } else {
        warn!(&ctx, "no start_seq op_code: {}, seq: {}", op_code, psn_seq);
        return Ok(xdp_action::XDP_ABORTED);
    };

    unsafe {
        (*eth_hdr_ptr).src_addr = flow_next_hop.src_mac;
        (*eth_hdr_ptr).dst_addr = flow_next_hop.dst_mac;
        (*udp_hdr_ptr).source = u16::to_be(new_udp_src_port);
        (*udp_hdr_ptr).dest = u16::to_be(3000);
        (*udp_hdr_ptr).len = u16::to_be(udp_len + SprayerHdr::LEN as u16);
        (*udp_hdr_ptr).check = 0;
        (*ipv4_hdr_ptr).tot_len = u16::to_be(ipv4_tot_len + SprayerHdr::LEN as u16);
        (*ipv4_hdr_ptr).check = 0;
    };

    let ip_csum = csum(ipv4_hdr_ptr as *const Ipv4Hdr as *mut u32, Ipv4Hdr::LEN as u32, 0);

    unsafe { (*ipv4_hdr_ptr).check = ip_csum};

    let eth_hdr = unsafe { eth_hdr_ptr.read() };
    let ipv4_hdr = unsafe { ipv4_hdr_ptr.read() };
    let udp_hdr = unsafe { udp_hdr_ptr.read() };
    let bth_hdr = unsafe { bth_hdr_ptr.read() };
    let sprayer_hdr = SprayerHdr{
        src_port: u16::from_be(udp_src_port),
        padding: 0,
        start_seq,
    };

    unsafe { bpf_xdp_adjust_head(ctx.ctx, -(SprayerHdr::LEN as i32)) };

    let eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    let ipv4_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let udp_hdr_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let sprayer_hdr_ptr = ptr_at_mut::<SprayerHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let bth_hdr_ptr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + SprayerHdr::LEN).ok_or(xdp_action::XDP_PASS)?;

    unsafe {
        eth_hdr_ptr.write(eth_hdr);
        ipv4_hdr_ptr.write(ipv4_hdr);
        udp_hdr_ptr.write(udp_hdr);
        sprayer_hdr_ptr.write(sprayer_hdr);
        bth_hdr_ptr.write(bth_hdr);
    }

    let res = unsafe { bpf_redirect(decap_intf.ifidx, 0) };
    Ok(res as u32)
}

#[inline(always)]
fn mask(port: u16, num: u32) -> u16 {
    port ^ num as u16
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
    if let Err(_e) = unsafe { FLOWTABLE.insert(&flow_key, &flow_next_hop, 0) }{
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

