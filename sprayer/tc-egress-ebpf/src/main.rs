#![no_std]
#![no_main]

use core::{mem, borrow::BorrowMut};

use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    helpers::bpf_skb_change_head,
    programs::TcContext,
    maps::HashMap,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};

#[map(name = "COUNTER")]
static mut COUNTER: HashMap<u16, u16> =
    HashMap::<u16, u16>::with_max_entries(1, 0);

#[map(name = "LINKS")]
static mut LINKS: HashMap<u16, u16> =
    HashMap::<u16, u16>::with_max_entries(1, 0);

#[map(name = "PORTS")]
static mut PORTS: HashMap<u16, u16> =
    HashMap::<u16, u16>::with_max_entries(64, 0);

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_tc_egress(mut ctx: TcContext) -> Result<i32, ()> {
    /* 
    let links = match unsafe { LINKS.get(&0) } {
        Some(links) => {
            links
        }
        None => {
            return Ok(TC_ACT_PIPE)
        }
    };

    let counter = match unsafe { COUNTER.get(&0) } {
        Some(counter) => {
            counter
        }
        None => {
            return Ok(TC_ACT_PIPE)
        }
    };
    
    
    let port = match unsafe { PORTS.get(counter) } {
        Some(port) => {
            port
        }
        None => {
            return Ok(TC_ACT_PIPE)
        }
    };
    */
    


    let ethhdr: EthHdr = match ctx.load(0).map_err(|_| ()){
        Ok(hdr) => {
            hdr
        }
        Err(_) => {
            return Ok(TC_ACT_PIPE)
        }
    };


    let (ip_proto_len, payload_len) = match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let mut ip_hdr: Ipv4Hdr = match ctx.load(EthHdr::LEN).map_err(|_| ()){
                Ok(hdr) => hdr,
                Err(_) => {
                    return Ok(TC_ACT_PIPE)
                }
            };
            let ip_tot_len = u16::from_be(ip_hdr.tot_len) + (EthHdr::LEN  + Ipv4Hdr::LEN + UdpHdr::LEN) as u16;
            ip_hdr.tot_len = u16::to_be(ip_tot_len);
            ip_hdr.proto = IpProto::Udp;
            
            unsafe {
                bpf_skb_change_head(ctx.skb.skb, (EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as u32, 0);
                //bpf_skb_change_head(ctx.skb.skb, 0, 0);
            }
            
            modify_context(&mut ctx, ip_hdr)?;
            
            (Ipv4Hdr::LEN, ip_tot_len - Ipv4Hdr::LEN as u16)
        },
        _ => {
            return Ok(TC_ACT_PIPE);
        }
    };

    
    match ctx.store(0, &ethhdr, 0){
        Ok(_) => {},
        Err(_) => {
            return Ok(TC_ACT_PIPE)
        }
    };

    
    let outer_udp_hdr = UdpHdr{
        source: u16::to_be(1000),
        dest: u16::to_be(3000),
        len: u16::to_be(payload_len),
        check: 0,
    };
    
 
    match ctx.store(EthHdr::LEN + ip_proto_len, &outer_udp_hdr, 0){
        Ok(_) => {},
        Err(_) => {
            return Ok(TC_ACT_PIPE)
        }
    };
    

    /*
    let mut new_counter = counter.clone() + 1;
    if new_counter == *links {
        new_counter = 0;
    }

    match unsafe { COUNTER.insert(&0, &new_counter, 0) }{
        Ok(_) => {
        },
        Err(_) => {
            return Ok(TC_ACT_PIPE)
        }
    }
    */
    
    
    Ok(TC_ACT_PIPE)
}

fn modify_context<O>(ctx: &mut TcContext, o: O) -> Result<(), ()> {
    match ctx.store(EthHdr::LEN, &o, 0){
        Ok(_) => {},
        Err(_) => {
            //info!(ctx, "store outer error");
            return Err(())
        }
    };
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)] // 
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &TcContext, offset: usize) -> Result<*mut T,()> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Ok(ptr as *mut T)
}
