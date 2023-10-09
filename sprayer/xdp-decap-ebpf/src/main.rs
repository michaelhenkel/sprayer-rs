#![no_std]
#![no_main]

use core::mem::{self, zeroed, size_of};

use aya_bpf::{
    bindings::{xdp_action, bpf_fib_lookup as fib_lookup, bpf_spin_lock as spin_lock},
    macros::{xdp, map},
    helpers::{
        bpf_redirect,
        bpf_fib_lookup,
        bpf_redirect_map,
        bpf_csum_diff,
        bpf_spin_lock,
        bpf_spin_unlock,
    },
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
};

#[map(name = "ENCAPINTERFACE")]
static mut ENCAPINTERFACE: HashMap<u32, Interface> =
    HashMap::<u32, Interface>::with_max_entries(1, 0);

#[map(name = "BUFFER")]
static mut BUFFER: HashMap<u8, u8> =
    HashMap::<u8, u8>::with_max_entries(1, 0);

#[map(name = "FLOWTABLE")]
static mut FLOWTABLE: HashMap<FlowKey, FlowNextHop> =
    HashMap::<FlowKey, FlowNextHop>::with_max_entries(256, 0);

#[map(name = "NEXTSEQ")]
static mut NEXTSEQ: HashMap<[u8;3], u32> =
    HashMap::<[u8;3], u32>::with_max_entries(2048, 0);

#[map(name = "LASTCOUNTER")]
static mut LASTCOUNTER: HashMap<[u8;3], [u8;3]> =
    HashMap::<[u8;3], [u8;3]>::with_max_entries(2048, 0);

#[map(name = "INGRESSXSKMAP")]
static mut XSKMAP: XskMap<u32, u32> =
    XskMap::<u32, u32>::with_max_entries(64, 0);

enum Action{
    BUFFER,
    REDIRECT
}

#[repr(C, packed)]
struct SpinLock {
    psn_seq: u32,
    lock: spin_lock,
}
/*

struct hash_elem {
    int cnt;
    struct bpf_spin_lock lock;
};
struct hash_elem * val = bpf_map_lookup_elem(&hash_map, &key);
if (val) {
    bpf_spin_lock(&val->lock);
    val->cnt++;
    bpf_spin_unlock(&val->lock);
}

*/
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

    let buf = match unsafe { BUFFER.get(&0) } {
        Some(buf) => {
            if *buf == 1 {
                true
            } else {
                false
            }
        }
        None => {
            true
        }
    };
    match try_xdp_decap(ctx, *intf, buf) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_decap(ctx: XdpContext, encap_intf: Interface, buf: bool) -> Result<u32, u32> {
    let eth_hdr_ptr = match ptr_at_mut::<EthHdr>(&ctx, 0){
        Some(eth_hdr_ptr) => eth_hdr_ptr,
        None => {
            return Ok(xdp_action::XDP_PASS)
        },
    };
    if unsafe{ (*eth_hdr_ptr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ipv4_hdr_ptr = match ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN){
        Some(ipv4_hdr_ptr) => ipv4_hdr_ptr,
        None => {
            return Ok(xdp_action::XDP_PASS)
        },
    
    };
    if unsafe { (*ipv4_hdr_ptr).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }
    let udp_hdr_ptr = match ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN){
        Some(udp_hdr_ptr) => udp_hdr_ptr,
        None => {
            warn!(&ctx,"udp_hdr_ptr is None");
            return Ok(xdp_action::XDP_PASS)
        },
    };
    if u16::from_be(unsafe { (*udp_hdr_ptr).dest } ) != 4791 {
        return Ok(xdp_action::XDP_PASS);
    };
    let bth_hdr_ptr = match ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN){
        Some(bth_hdr_ptr) => bth_hdr_ptr,
        None => {
            warn!(&ctx,"bth_hdr_ptr is None");
            return Ok(xdp_action::XDP_PASS)
        },
    };

    let res = u8::from_be(unsafe { (*bth_hdr_ptr).res });
    let psn_seq_list = unsafe { (*bth_hdr_ptr).psn_seq };
    let psn_seq: u32 = u32::from_be_bytes([0, psn_seq_list[0], psn_seq_list[1], psn_seq_list[2]]);
    let dst_qp_list = unsafe { (*bth_hdr_ptr).dest_qpn };
    let op_code = u8::from_be(unsafe { (*bth_hdr_ptr).opcode });
    let udp_source_port = u16::from_be(unsafe { (*udp_hdr_ptr).source } );
    let orig_udp_src_port = unmask(udp_source_port, psn_seq);

    unsafe { (*udp_hdr_ptr).source = u16::to_be(orig_udp_src_port); }

    let flow_next_hop = if let Some(flow_next_hop) = get_v4_next_hop_from_flow_table(&ctx){
        flow_next_hop
    } else if let Some(flow_next_hop) = get_next_hop(&ctx) {
        flow_next_hop
    } else {
        warn!(&ctx,"next_hop not found");
        return Ok(xdp_action::XDP_PASS);
    };

    unsafe {
        (*eth_hdr_ptr).src_addr = flow_next_hop.src_mac;
        (*eth_hdr_ptr).dst_addr = flow_next_hop.dst_mac;
        (*udp_hdr_ptr).check = 0;
    };

    let action = if buf {
        //warn!(&ctx, "got psn_seq: {}", psn_seq);
        if op_code == 17 {
            Action::REDIRECT
        } else if op_code == 0 && res == 1{
            match unsafe { NEXTSEQ.insert(&dst_qp_list, &(psn_seq + 1), 0)}{
                Ok(_) => {
                    unsafe { (*bth_hdr_ptr).res = 0 };
                }
                Err(_) => {
                    warn!(&ctx,"failed to insert next_seq");
                    return Ok(xdp_action::XDP_ABORTED);
                }
            };
            //warn!(&ctx, "0 psn_seq: {}, next_seq: {}", psn_seq, psn_seq+1);
            Action::REDIRECT
        } else if let Some(next_seq) = unsafe { NEXTSEQ.get(&dst_qp_list) }{
            if *next_seq == psn_seq {
                if op_code == 2 {
                    if let Some(last_counter) = unsafe { LASTCOUNTER.get_ptr_mut(&dst_qp_list)}{
                        let last_counter_list = unsafe { *last_counter };
                        let mut fc: u32 = u32::from_be_bytes([0, last_counter_list[0], last_counter_list[1], last_counter_list[2]]);
                        fc += 1;
                        let fc_bytes = fc.to_be_bytes();
                        let fc_list: [u8;3] = [fc_bytes[1], fc_bytes[2], fc_bytes[3]];
                        unsafe { *last_counter = fc_list };
                    } else {
                        let fc: u32 = 1;
                        let fc_bytes = fc.to_be_bytes();
                        let fc_list: [u8;3] = [fc_bytes[1], fc_bytes[2], fc_bytes[3]];
                        match unsafe { LASTCOUNTER.insert(&dst_qp_list, &fc_list, 0) }{
                            Ok(_) => {},
                            Err(_) => {
                                warn!(&ctx,"failed to insert last_counter");
                                return Ok(xdp_action::XDP_ABORTED);
                            }
                        };
                    }
                }
                match unsafe { NEXTSEQ.insert(&dst_qp_list, &(psn_seq + 1), 0)}{
                    Ok(_) => {}
                    Err(_) => {
                        warn!(&ctx,"failed to insert next_seq");
                        return Ok(xdp_action::XDP_ABORTED);
                    }
                };
                //warn!(&ctx, "psn_seq: {}, next_seq: {}", psn_seq, psn_seq+1);
                Action::REDIRECT
            } else {
                //warn!(&ctx, "buffering psn_seq: {}, expected next_seq: {}", psn_seq, *next_seq);
                Action::BUFFER
            }
        } else {
            //warn!(&ctx, "buffering psn_seq: {} map empty", psn_seq);
            Action::BUFFER
        }
    } else {
        Action::REDIRECT
    };
    //action = Action::BUFFER;

    let res = match action {
        Action::REDIRECT => {
            unsafe { bpf_redirect(encap_intf.ifidx, 0) as u32 }
        },
        Action::BUFFER => {
            let idx = unsafe { (*ctx.ctx).rx_queue_index };
            let map_ptr = unsafe { &mut XSKMAP as *mut _ as *mut c_void };
            unsafe { bpf_redirect_map(map_ptr, idx as u64, 0) as u32}
        },
    };

    Ok(res)
}

#[inline(always)]
fn unmask(port: u16, num: u32) -> u16 {
    port ^ num as u16
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
    let ipv4_hdr_ptr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let udp_hdr_ptr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let mut flow_key: FlowKey = unsafe { zeroed() };
    flow_key.dst_ip = unsafe { (*ipv4_hdr_ptr).dst_addr };
    flow_key.src_ip = unsafe { (*ipv4_hdr_ptr).src_addr };
    flow_key.dst_port = unsafe { (*udp_hdr_ptr).dest };
    flow_key.src_port = unsafe { (*udp_hdr_ptr).source };
    flow_key.ip_proto = unsafe { (*ipv4_hdr_ptr).proto as u8 };
    match unsafe { FLOWTABLE.get(&flow_key) } {
        Some(fnh) => {
            return Some(fnh.clone())
        }
        None => {
            warn!(ctx, "flow_next_hop not found");
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
        warn!(ctx,"fib lookup failed for dst ip {:i}, ret {}",dst_ip, ret);
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
        warn!(ctx, "failed to insert flow_next_hop");
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