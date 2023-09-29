#![no_std]
#![no_main]

use core::mem::{self, zeroed, size_of};

use aya_bpf::{
    bindings::{xdp_action, bpf_fib_lookup as fib_lookup},
    macros::{xdp, map},
    helpers::{bpf_xdp_adjust_head, bpf_xdp_adjust_tail, bpf_redirect, bpf_fib_lookup, bpf_redirect_map},
    programs::XdpContext,
    maps::HashMap, cty::c_void, 
};
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use common::{Interface, FlowKey, FlowNextHop, SrcDst, BthHdr, Bth, XskMap};

#[repr(C)]
#[derive(Clone, Copy)]
struct ControlMsg{
    msg_type: u32,
}
enum BufferReason {
    MiddleAfterLast,
    FirstMissingForLast,
    FirstMissingForMiddle,
    MiddlePsnSeqMismatch,
    MiddleMissesPrevious,
    LastPsnSeqMismatch,
    FirstPsnSeqMismatch,
    LastAfterLast,
    FirstAfterFirst,
    FirstAfterMiddle,
    FirstAfterLast,
    LastMissesPrevious,
    Custom,
}

impl BufferReason{
    fn msg(self) -> &'static str {
        match self {
            BufferReason::MiddleAfterLast => "middle after last",
            BufferReason::FirstMissingForLast => "first missing for last",
            BufferReason::FirstMissingForMiddle => "first missing for middle",
            BufferReason::MiddlePsnSeqMismatch => "middle psn seq mismatch",
            BufferReason::LastPsnSeqMismatch => "last psn seq mismatch",
            BufferReason::LastAfterLast => "last after last",
            BufferReason::FirstAfterFirst => "first after first",
            BufferReason::FirstAfterMiddle => "first after middle",
            BufferReason::FirstAfterLast => "first after last",
            BufferReason::FirstPsnSeqMismatch => "first psn seq mismatch",
            BufferReason::MiddleMissesPrevious => "middle misses previous",
            BufferReason::LastMissesPrevious => "last misses previous",
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

#[map(name = "BUFFERCOUNTER")]
static mut BUFFERCOUNTER: HashMap<u8, u32> =
    HashMap::<u8, u32>::with_max_entries(1, 0);

#[map(name = "INGRESSXSKMAP")]
static mut XSKMAP: XskMap<u32, u32> =
    XskMap::<u32, u32>::with_max_entries(64, 0);
#[xdp]
pub fn xdp_decap(ctx: XdpContext) -> u32 {
    let intf = match unsafe { ENCAPINTERFACE.get(&0) } {
        Some(intf) => {
            intf
        }
        None => {
            //info!(&ctx, "encap intf not found");
            return xdp_action::XDP_ABORTED
        }
    };
    match try_xdp_decap(ctx, *intf) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_decap(ctx: XdpContext, encap_intf: Interface) -> Result<u32, u32> {
    let eth = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    let eth_type = u16::from_be(unsafe { (*eth).ether_type as u16});
    if unsafe{ (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ip).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }
    let src_address = unsafe { (*ip).src_addr };
    let dst_address = unsafe { (*ip).dst_addr };
    let udp = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let udp_dest = unsafe { u16::from_be((*udp).dest) };
    let res = if udp_dest == 3000 {
        unsafe { bpf_xdp_adjust_head(ctx.ctx, (EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as i32)};
        let inner_eth = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
        if unsafe{ (*inner_eth).ether_type } != EtherType::Ipv4 {
            return Ok(xdp_action::XDP_PASS);
        }
        let bth_hdr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
        let op_code = unsafe { u8::from_be((*bth_hdr).opcode) };
        let psn_seq_list = unsafe { (*bth_hdr).psn_seq };
        let psn_seq = u32::from_be_bytes([0, psn_seq_list[0], psn_seq_list[1], psn_seq_list[2]]);
        info!(&ctx, "udp psn seq: {}", psn_seq);
        let dst_qp_list = unsafe { (*bth_hdr).dest_qpn };
        let dst_qp = u32::from_be_bytes([0, dst_qp_list[0], dst_qp_list[1], dst_qp_list[2]]);

        let mut current_bth = unsafe { zeroed::<Bth>()};
        current_bth.opcode = op_code;
        current_bth.cur_psn_seq = psn_seq;
        
        let buffer_reason: Option<BufferReason> = 
        if op_code == 0 {
            info!(&ctx, "first");
            current_bth.first_psn_seq = psn_seq;
            match unsafe { BTHMAP.get_ptr_mut(&dst_qp)} {
                Some(previous_bth_ptr) => {
                    current_bth.out_of_order = 1;
                    current_bth.prev_psn_seq = unsafe { (*previous_bth_ptr).next_psn_seq };
                    if unsafe { (*previous_bth_ptr).opcode == 1 } {
                        Some(BufferReason::FirstAfterMiddle)
                    } else if unsafe { (*previous_bth_ptr).opcode == 2 } {
                        Some(BufferReason::FirstAfterLast)
                    } else if unsafe { (*previous_bth_ptr).opcode == 0 } {
                        Some(BufferReason::FirstAfterFirst)
                    } else {
                        return Ok(xdp_action::XDP_ABORTED)
                    }
                },
                None => {
                    current_bth.prev_psn_seq = 0;
                    current_bth.out_of_order = 0;
                    current_bth.first_psn_seq = psn_seq;
                    let next_seq = psn_seq + 1;
                    current_bth.next_psn_seq = next_seq;
                    None
                }
            }
        } else if op_code == 1 {
            info!(&ctx, "middle");
            match unsafe { BTHMAP.get_ptr_mut(&dst_qp)} {
                Some(previous_bth_ptr) => {
                    if unsafe { (*previous_bth_ptr).next_psn_seq } == psn_seq {
                        current_bth.out_of_order = 0;
                        current_bth.prev_psn_seq = unsafe { (*previous_bth_ptr).cur_psn_seq };
                        let next_seq = psn_seq + 1;
                        current_bth.next_psn_seq = next_seq;
                        current_bth.first_psn_seq = unsafe { (*previous_bth_ptr).first_psn_seq };
                        None
                    } else {
                        current_bth.out_of_order = 1;
                        current_bth.prev_psn_seq = unsafe { (*previous_bth_ptr).cur_psn_seq };
                        current_bth.first_psn_seq = unsafe { (*previous_bth_ptr).first_psn_seq };
                        Some(BufferReason::MiddlePsnSeqMismatch)
                    }
                },
                None => {
                    current_bth.prev_psn_seq = 0;
                    current_bth.out_of_order = 1;
                    Some(BufferReason::MiddleMissesPrevious)
                }
            }
        } else if op_code == 2 {
            info!(&ctx, "last");
            match unsafe { BTHMAP.get_ptr_mut(&dst_qp)} {
                Some(previous_bth_ptr) => {
                    if unsafe { (*previous_bth_ptr).next_psn_seq } == psn_seq {
                        current_bth.out_of_order = 0;
                        current_bth.prev_psn_seq = unsafe { (*previous_bth_ptr).cur_psn_seq };
                        current_bth.first_psn_seq = unsafe { (*previous_bth_ptr).first_psn_seq };
                        None
                    } else {
                        current_bth.out_of_order = 1;
                        current_bth.prev_psn_seq = unsafe { (*previous_bth_ptr).cur_psn_seq };
                        current_bth.first_psn_seq = unsafe { (*previous_bth_ptr).first_psn_seq };
                        Some(BufferReason::LastPsnSeqMismatch)
                    }
                },
                None => {
                    current_bth.prev_psn_seq = 0;
                    current_bth.out_of_order = 1;
                    Some(BufferReason::LastMissesPrevious)
                }
            }
        } else {
            info!(&ctx, "unknown");
            return Ok(xdp_action::XDP_ABORTED)
        };

        if let Err(_e) = unsafe { BTHMAP.insert(&dst_qp, &current_bth, 0) }{
            return Ok(xdp_action::XDP_ABORTED)
        }       
        let flow_next_hop = if let Some(flow_next_hop) = get_v4_next_hop_from_flow_table(&ctx){
            flow_next_hop
        } else if let Some(flow_next_hop) = get_next_hop(&ctx) {
            flow_next_hop
        } else {
            return Ok(xdp_action::XDP_PASS);
        };
        unsafe { (*inner_eth).src_addr = flow_next_hop.src_mac };
        unsafe { (*inner_eth).dst_addr = flow_next_hop.dst_mac };
        match buffer_reason{
            Some(buffer_reason) => {
                unsafe { bpf_xdp_adjust_head(ctx.ctx, -(Bth::LEN as i32))};
                let bth_hdr_ptr = ptr_at_mut::<Bth>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
                let mut new_bth = unsafe { zeroed::<Bth>()};
                new_bth.opcode = current_bth.opcode;
                new_bth.first_psn_seq = current_bth.first_psn_seq;
                new_bth.prev_psn_seq = current_bth.prev_psn_seq;
                new_bth.cur_psn_seq = current_bth.cur_psn_seq;
                new_bth.next_psn_seq = current_bth.next_psn_seq;
                new_bth.out_of_order = current_bth.out_of_order;
                unsafe { bth_hdr_ptr.write(new_bth)};
                buffer(&ctx, buffer_reason)
            },
            None => {
                unsafe { bpf_redirect(encap_intf.ifidx, 0) as u32 } 
            }
        }
    }
    else {
        xdp_action::XDP_PASS.into()
    };
    Ok(res)
}

#[inline(always)]
fn buffer(ctx: &XdpContext, buffer_reason: BufferReason) -> u32 {
    info!(ctx, "buffer reason: {}", buffer_reason.msg());
    match unsafe { BUFFERCOUNTER.get_ptr_mut(&0) } {
        Some(counter_ptr) => {
            unsafe { *counter_ptr += 1 };
            //info!(ctx, "buffer counter x: {}", unsafe { *counter_ptr })
        },
        None => {
            let counter = 1;
            if let Err(_e) = unsafe { BUFFERCOUNTER.insert(&0, &counter, 0) }{
                //warn!(ctx, "buffer counter insert failed");
            }
        }
    }
    let idx = unsafe { (*ctx.ctx).rx_queue_index };
    let map_ptr = unsafe { &mut XSKMAP as *mut _ as *mut c_void };
    unsafe { bpf_redirect_map(map_ptr, idx as u64, 0) as u32}
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
            info!(ctx, "flow_next_hop not found");
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
        info!(ctx,"fib lookup failed for dst ip {:i}, ifidx {}, ret {}",dst_ip, if_idx, ret);
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
