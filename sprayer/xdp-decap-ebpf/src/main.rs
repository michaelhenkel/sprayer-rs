#![no_std]
#![no_main]

use core::mem::{self, zeroed, size_of};

use aya_bpf::{
    bindings::{xdp_action, bpf_fib_lookup as fib_lookup},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_redirect, bpf_fib_lookup, bpf_redirect_map, bpf_csum_diff},
    programs::XdpContext,
    maps::HashMap, cty::c_void, 
};
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto, self},
    udp::UdpHdr,
};
use common::{Interface, FlowKey, FlowNextHop, SrcDst, BthHdr, Bth, XskMap, SprayerHdr, QpFirst};

#[repr(C)]
#[derive(Clone, Copy)]
struct ControlMsg{
    msg_type: u32,
}
enum BufferReason {
    Custom,
}

impl BufferReason{
    fn msg(self) -> &'static str {
        match self {
            BufferReason::Custom => "custom",
        }
    }
}

#[map(name = "ENCAPINTERFACE")]
static mut ENCAPINTERFACE: HashMap<u32, Interface> =
    HashMap::<u32, Interface>::with_max_entries(1, 0);

#[map(name = "FLOWTABLE")]
static mut FLOWTABLE: HashMap<FlowKey, FlowNextHop> =
    HashMap::<FlowKey, FlowNextHop>::with_max_entries(256, 0);

#[map(name = "BTHMAP")]
static mut BTHMAP: HashMap<u32, Bth> =
    HashMap::<u32, Bth>::with_max_entries(1024, 0);

#[map(name = "QPSEQMAP")]
static mut QPSEQMAP: HashMap<QpFirst, u32> =
    HashMap::<QpFirst, u32>::with_max_entries(2048, 0);

#[map(name = "BUFFERCOUNTER")]
static mut BUFFERCOUNTER: HashMap<u8, u32> =
    HashMap::<u8, u32>::with_max_entries(1, 0);

#[map(name = "INGRESSXSKMAP")]
static mut XSKMAP: XskMap<u32, u32> =
    XskMap::<u32, u32>::with_max_entries(64, 0);

enum Action{
    BUFFER,
    REDIRECT
}
#[xdp]
pub fn xdp_decap(ctx: XdpContext) -> u32 {
    let intf = match unsafe { ENCAPINTERFACE.get(&0) } {
        Some(intf) => {
            intf
        }
        None => {
            //////info!{&ctx, "encap intf not found");
            return xdp_action::XDP_ABORTED
        }
    };
    match try_xdp_decap(ctx, *intf) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_decap(ctx: XdpContext, encap_intf: Interface) -> Result<u32, u32> {
    info!(&ctx, "xdp_decap");
    let eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    if unsafe{ (*eth_hdr_ptr).ether_type } != EtherType::Ipv4 {
        info!(&ctx, "not ipv4");
        return Ok(xdp_action::XDP_PASS);
    }
    let ipv4_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ipv4_hdr_ptr).proto } != IpProto::Udp {
        info!(&ctx, "not udp");
        return Ok(xdp_action::XDP_PASS);
    }
    let udp_hdr_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    if u16::from_be(unsafe { (*udp_hdr_ptr).dest } ) != 3000 {
        info!(&ctx,"no sprayer proto");
        return Ok(xdp_action::XDP_PASS);
    }
    let sprayer_hdr_ptr = ptr_at_mut::<SprayerHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let bth_hdr_ptr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + SprayerHdr::LEN).ok_or(xdp_action::XDP_PASS)?;

    let mut eth_hdr = unsafe { eth_hdr_ptr.read() };
    let mut ipv4_hdr = unsafe { ipv4_hdr_ptr.read() };
    let mut udp_hdr = unsafe { udp_hdr_ptr.read() };
    let sprayer_hdr = unsafe { sprayer_hdr_ptr.read() };
    let bth_hdr = unsafe { bth_hdr_ptr.read() };

    let op_code = u8::from_be(bth_hdr.opcode);
    let dst_qpn = u32::from_be_bytes([0, bth_hdr.dest_qpn[0], bth_hdr.dest_qpn[1], bth_hdr.dest_qpn[2]]);
    let first = u32::from_be_bytes([0, sprayer_hdr.first[0], sprayer_hdr.first[1], sprayer_hdr.first[2]]);
    let qp_first = QpFirst { dst_qpn, first };
    let seq_num = u32::from_be_bytes([0, bth_hdr.psn_seq[0], bth_hdr.psn_seq[1], bth_hdr.psn_seq[2]]);

    info!(&ctx, "op_code {}, dst_qp {}, first {}, seq_num {}", op_code, dst_qpn, first, seq_num);

    let action = if op_code == 0 {
        info!(&ctx, "first packet");
        if let Some(next_seq_num) = unsafe { QPSEQMAP.get_ptr_mut(&qp_first) }{
            info!(&ctx, "first out of order, buffering");
            unsafe { *next_seq_num = seq_num };
            Action::BUFFER
        } else {
            unsafe { QPSEQMAP.insert(&qp_first, &(seq_num + 1), 0) }.map_err(|_| xdp_action::XDP_PASS)?;
            info!(&ctx, "first in order, redirecting");
            Action::REDIRECT
        }
    } else if op_code == 1 {
        if let Some(next_seq_num) = unsafe { QPSEQMAP.get_ptr_mut(&qp_first) }{
            if unsafe { *next_seq_num } == seq_num {
                unsafe { *next_seq_num = seq_num + 1 };
                info!(&ctx, "middle in order, redirecting");
                Action::REDIRECT
            } else {
                info!(&ctx, "middle out of order, buffering");
                Action::BUFFER
            }
            
        } else {
            info!(&ctx, "first not found for middle, buffering");
            unsafe { QPSEQMAP.insert(&qp_first, &0, 0) }.map_err(|_| xdp_action::XDP_PASS)?;
            Action::BUFFER
        }
    } else if op_code == 2{
        if let Some(next_seq_num) = unsafe { QPSEQMAP.get_ptr_mut(&qp_first) }{
            if unsafe { *next_seq_num } == seq_num  {
                unsafe { QPSEQMAP.remove(&qp_first) }.map_err(|_| xdp_action::XDP_PASS)?;
                info!(&ctx, "last in order, redirecting");
                Action::REDIRECT
            } else {
                info!(&ctx, "last out of order, buffering");
                Action::BUFFER
            }
        } else {
            info!(&ctx, "last not found for middle, buffering");
            unsafe { QPSEQMAP.insert(&qp_first, &0, 0) }.map_err(|_| xdp_action::XDP_PASS)?;
            Action::BUFFER
        }
    } else {
        info!(&ctx, "unknown opcode, redirecting");
        Action::REDIRECT
    };

    let flow_next_hop = if let Some(flow_next_hop) = get_v4_next_hop_from_flow_table(&ctx){
        flow_next_hop
    } else if let Some(flow_next_hop) = get_next_hop(&ctx) {
        flow_next_hop
    } else {
        return Ok(xdp_action::XDP_PASS);
    };
    eth_hdr.src_addr = flow_next_hop.src_mac;
    eth_hdr.dst_addr = flow_next_hop.dst_mac;
    ipv4_hdr.check = 0;
    let new_ipv4_tot_len = u16::from_be(ipv4_hdr.tot_len) - SprayerHdr::LEN as u16;
    ipv4_hdr.tot_len = u16::to_be(new_ipv4_tot_len);
    ipv4_hdr.check = csum(&ipv4_hdr.clone() as *const Ipv4Hdr as *mut u32, Ipv4Hdr::LEN as u32, 0);
    udp_hdr.source = sprayer_hdr.src_port;
    let udp_len = u16::from_be(udp_hdr.len) as usize - SprayerHdr::LEN;
    udp_hdr.len = u16::to_be(udp_len as u16);
    udp_hdr.dest = u16::to_be(4791);

    let res = match action {
        Action::REDIRECT => {
            unsafe {
                bpf_xdp_adjust_head(ctx.ctx, SprayerHdr::LEN as i32);
            }

            let bth_hdr_ptr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
            unsafe { bth_hdr_ptr.write(bth_hdr) };
            info!(&ctx, "redirecting");
            unsafe { bpf_redirect(encap_intf.ifidx, 0) as u32 }
        },
        Action::BUFFER => {
            info!(&ctx, "buffering");
            let idx = unsafe { (*ctx.ctx).rx_queue_index };
            let map_ptr = unsafe { &mut XSKMAP as *mut _ as *mut c_void };
            unsafe { bpf_redirect_map(map_ptr, idx as u64, 0) as u32}
        },
    };
    let eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    unsafe { eth_hdr_ptr.write(eth_hdr) };
    let ipv4_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    unsafe { ipv4_hdr_ptr.write(ipv4_hdr) };
    let udp_hdr_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    unsafe { udp_hdr_ptr.write(udp_hdr) };

    Ok(res)
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
            ////info!{ctx, "flow_next_hop not found");
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
        ////info!{ctx,"fib lookup failed for dst ip {:i}, ifidx {}, ret {}",dst_ip, if_idx, ret);
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