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
use common::{Interface, FlowKey, FlowNextHop, SrcDst, BthHdr, Bth, XskMap, SprayerHdr};

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
static mut QPSEQMAP: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(2048, 0);

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
    let eth = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    //let eth_type = u16::from_be(unsafe { (*eth).ether_type as u16});
    if unsafe{ (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ip).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }
    let udp = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let udp_dest = unsafe { u16::from_be((*udp).dest) };
    let res = if udp_dest == 3000 {

        let bth_hdr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + SprayerHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
        let op_code = unsafe { u8::from_be((*bth_hdr).opcode) };
        let psn_seq_list = unsafe { (*bth_hdr).psn_seq };
        let psn_seq = u32::from_be_bytes([0, psn_seq_list[0], psn_seq_list[1], psn_seq_list[2]]);
        let dst_qp_list = unsafe { (*bth_hdr).dest_qpn };
        let dst_qp = u32::from_be_bytes([0, dst_qp_list[0], dst_qp_list[1], dst_qp_list[2]]);
        info!(&ctx, "op_code: {}, psn_seq: {}, dst_qp: {}", op_code, psn_seq, dst_qp);  
        let sprayer_hdr = ptr_at_mut::<SprayerHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
        let src_port = unsafe { u16::from_be((*sprayer_hdr).src_port) };
        let qp_id_list = unsafe { (*sprayer_hdr).qp_id };
        let qp_id = u32::from_be_bytes([0, qp_id_list[0], qp_id_list[1], qp_id_list[2]]);
        info!(&ctx, "src_port: {}, qp_id: {}", src_port, qp_id);


        


        
        
        let mut buffer_reason: Option<BufferReason> = 
        if op_code == 0 {
            match unsafe { QPSEQMAP.get_ptr_mut(&dst_qp)}{
                Some(next_seq_num) => {
                    unsafe { *next_seq_num = psn_seq };
                    Some(BufferReason::Custom)
                },
                None => {
                    if let Err(e) = unsafe { QPSEQMAP.insert(&dst_qp, &(psn_seq + 1), 0) }{
                        warn!(&ctx, "qpseqmap insert failed {}",e);
                        return Ok(xdp_action::XDP_ABORTED)
                    }
                    None
                }
            }
        } else if op_code == 1 {
            match unsafe { QPSEQMAP.get_ptr_mut(&dst_qp)}{
                Some(next_seq_num) => {
                    if unsafe { *next_seq_num }== psn_seq {
                        unsafe { *next_seq_num = psn_seq + 1 };
                        None
                    } else {
                        Some(BufferReason::Custom)
                    }
                },
                None => {
                    if let Err(e) = unsafe { QPSEQMAP.insert(&dst_qp, &0, 0) }{
                        warn!(&ctx, "qpseqmap insert failed {}",e);
                        return Ok(xdp_action::XDP_ABORTED)
                    }
                    Some(BufferReason::Custom)
                }
            }
        } else if op_code == 2 {
            match unsafe { QPSEQMAP.get_ptr_mut(&dst_qp)}{
                Some(next_seq_num) => {
                    if unsafe { *next_seq_num }== psn_seq  {
                        None
                    } else {
                        Some(BufferReason::Custom)
                    }
                },
                None => {
                    if let Err(e) = unsafe { QPSEQMAP.insert(&dst_qp, &0, 0) }{
                        warn!(&ctx, "qpseqmap insert failed {}",e);
                        return Ok(xdp_action::XDP_ABORTED)
                    }
                    Some(BufferReason::Custom)
                }
            }
        } else {
            None
        };
        let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
        let new_eth_hdr = unsafe { eth_hdr.read()};
        let flow_next_hop = if let Some(flow_next_hop) = get_v4_next_hop_from_flow_table(&ctx){
            flow_next_hop
        } else if let Some(flow_next_hop) = get_next_hop(&ctx) {
            flow_next_hop
        } else {
            return Ok(xdp_action::XDP_PASS);
        };
        unsafe { (*eth_hdr).src_addr = flow_next_hop.src_mac };
        unsafe { (*eth_hdr).dst_addr = flow_next_hop.dst_mac };
        buffer_reason = None;
        match buffer_reason{
            Some(_buffer_reason) => {
                let idx = unsafe { (*ctx.ctx).rx_queue_index };
                let map_ptr = unsafe { &mut XSKMAP as *mut _ as *mut c_void };
                unsafe { bpf_redirect_map(map_ptr, idx as u64, 0) as u32}
            },
            None => {
                let ip_hdr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
                let mut new_ip_hdr = unsafe { ip_hdr.read()};
                new_ip_hdr.check = 0;
                let ip_csum = csum(&new_ip_hdr.clone() as *const Ipv4Hdr as *mut u32, Ipv4Hdr::LEN as u32, 0);
                new_ip_hdr.check = ip_csum;

                let udp_hdr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
                let mut new_udp_hdr = unsafe { udp_hdr.read()};
                new_udp_hdr.source = u16::to_be(src_port);
                unsafe { bpf_xdp_adjust_head(ctx.ctx, SprayerHdr::LEN as i32) };
                let bth_hdr = ptr_at_mut::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
                unsafe { (*bth_hdr).dest_qpn = qp_id_list };
                let new_eth_hdr_ptr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
                let new_ip_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
                let new_udp_hdr_ptr = ptr_at_mut::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(xdp_action::XDP_PASS)?;
                unsafe {
                    new_eth_hdr_ptr.write(new_eth_hdr);
                    new_ip_hdr_ptr.write(new_ip_hdr);
                    new_udp_hdr_ptr.write(new_udp_hdr);
                }
                let qp_id_list = unsafe { (*bth_hdr).dest_qpn };
                let qp_id = u32::from_be_bytes([0, qp_id_list[0], qp_id_list[1], qp_id_list[2]]);
                info!(&ctx, "qp_id: {}", qp_id);

                unsafe { bpf_redirect(encap_intf.ifidx, 0) as u32 } 
            }
        }
        
        //unsafe { bpf_redirect(encap_intf.ifidx, 0) as u32 } 
    }
    else {
        xdp_action::XDP_PASS.into()
    };
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
