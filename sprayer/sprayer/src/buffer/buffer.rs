use aya::Bpf;
use aya::maps::HashMap;
use common::BthHdr;
use log::{info, warn};
use arraydeque::{ArrayDeque, Wrapping};
use afxdp::mmap_area::{MmapArea, MmapAreaOptions};
use afxdp::socket::{Socket, SocketOptions, SocketRx, SocketTx};
use afxdp::umem::{Umem, UmemCompletionQueue, UmemFillQueue};
use afxdp::PENDING_LEN;
use afxdp::{buf::Buf, buf_mmap::BufMmap};
use libbpf_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS,
    xsk_socket__update_xskmap,
    xsk_socket,
};
use std::collections::HashMap as ColHashMap;
use std::sync::Arc;
use std::cmp::min;
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    udp::UdpHdr,
};
use common::QpSeq;
#[derive(Default, Copy, Clone)]
pub struct BufCustom {}

const BUFF_SIZE: usize = 4096;
const BUF_NUM: usize = 65535 * 4;
const BATCH_SIZE: usize = 64;
const FILL_THRESHOLD: usize = 64;

pub struct Buffer{
    ingress_intf: String,
    egress_intf: String,
    ingress_map_fd: i32,
    egress_map_fd: i32,
    xdp_decap_bpf: Bpf,
    xdp_encap_bpf: Bpf,
}
impl Buffer {
    pub fn new(ingress_intf: String, egress_intf: String, ingress_map_fd: i32, egress_map_fd: i32, xdp_decap_bpf: Bpf, xdp_encap_bpf: Bpf) -> Buffer {
        Buffer{
            ingress_intf,
            egress_intf,
            ingress_map_fd,
            egress_map_fd,
            xdp_decap_bpf,
            xdp_encap_bpf,
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()>{
        let options = MmapAreaOptions{ huge_tlb: false };
        let map_area = MmapArea::new(BUF_NUM, BUFF_SIZE, options);
        let (area, mut bufs) = match map_area {
            Ok((area, bufs)) => (area, bufs),
            Err(err) => panic!("no mmap for you: {:?}", err),
        };
        let mut rx_state = State::new(area.clone(), &mut bufs, StateType::Rx, self.ingress_intf.clone(), self.ingress_map_fd);
        let mut tx_state = State::new(area.clone(), &mut bufs, StateType::Tx, self.egress_intf.clone(), self.egress_map_fd);
        let mut queue_ring: ColHashMap<([u8;3],u32),BufMmap<BufCustom>> = ColHashMap::new();

        let rx = match rx_state.socket{
            SocketType::Rx(ref mut rx) => { Some(rx) }
            _ => None,
        };
        let rx = rx.unwrap();

        let tx = match tx_state.socket{
            SocketType::Tx(ref mut tx) => { Some(tx) }
            _ => None,
        };
        let tx = tx.unwrap();
        let custom = BufCustom {};
        let next_seq_map = self.xdp_decap_bpf.map_mut("NEXTSEQ").unwrap();
        let mut next_seq_map: HashMap<_, [u8;3], u32> = HashMap::try_from(next_seq_map)?;
        let mut last_seq = ([0u8;3], 0);
        //let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(1));
        loop {
            let r = rx_state.cq.service(&mut bufs, BATCH_SIZE);
            match r {
                Ok(n) => {
                    if n > 0 {
                        warn!("serviced {} packets", n)
                    }
                  
                }
                Err(err) => panic!("error: {:?}", err),
            }
            match rx.try_recv(&mut rx_state.v, BATCH_SIZE, custom) {
                Ok(n) => {
                    if n > 0 {
                        rx_state.fq_deficit += n;
                        //warn!("received {} packets", n);
                        while let Some(v) = rx_state.v.pop_front(){
                            let data: &[u8] = v.get_data();
                            let data_ptr = data.as_ptr() as usize;
                            let bth_hdr = (data_ptr + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *const BthHdr;
                            let dst_qp = unsafe { (*bth_hdr).dest_qpn };
                            let seq_num = {
                                let seq_num = unsafe { (*bth_hdr).psn_seq };
                                u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]])
                            };
                            //warn!("adding seq_num: {} to ring", seq_num);
                            queue_ring.insert((dst_qp, seq_num), v);
                        }
                        if queue_ring.len() > 0 {                
                            for res in next_seq_map.iter(){
                                if let Ok((dst_qpn, mut seq)) = res {
                                    while let Some(v) = queue_ring.remove(&(dst_qpn, seq)){
                                        last_seq = (dst_qpn, seq);
                                        tx_state.v.push_back(v);
                                        seq += 1;
                                    }
                                }
                            }
                        }
                        
                    } else {
                        if rx_state.fq.needs_wakeup() {
                            rx.wake();
                        }
                    }
                }
                Err(err) => {
                    panic!("error: {:?}", err);
                }
            }
            if queue_ring.len() > 0 {   
                //interval.tick().await; 
                for res in next_seq_map.iter(){
                    if let Ok((dst_qpn, mut seq)) = res {
                        while let Some(v) = queue_ring.remove(&(dst_qpn, seq)){
                            last_seq = (dst_qpn, seq);
                            tx_state.v.push_back(v);
                            seq += 1;
                        }
                    }
                }
            }
            for (k,v) in queue_ring.drain(){
                tx_state.v.push_back(v);
            }
            if !tx_state.v.is_empty() {
                if tx.try_send(&mut tx_state.v, BATCH_SIZE).is_ok(){
                    
                }
            }
            if last_seq.0 != [0,0,0] && last_seq.1 > 0{
                next_seq_map.insert(last_seq.0, last_seq.1+1, 0)?;
            }
            if rx_state.fq_deficit >= FILL_THRESHOLD {
                let r = rx_state.fq.fill(&mut bufs, rx_state.fq_deficit);
                match r {
                    Ok(n) => {
                        warn!("filling {} buffers", n);
                        rx_state.fq_deficit -= n;
                    }
                    Err(err) => panic!("error: {:?}", err),
                }
            }

        }
    }
}

#[inline(always)]
fn int_to_mac(mut value: i64) -> String {
    let mut bytes = [0u8; 6];
    for i in (0..6).rev() {
        bytes[i] = (value & 0xff) as u8;
        value >>= 8;
    }
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
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

pub struct State<'a>{
    pub cq: UmemCompletionQueue<'a, BufCustom>,
    pub fq: UmemFillQueue<'a, BufCustom>,
    pub socket: SocketType<'a>,
    pub v: ArrayDeque<[BufMmap<'a, BufCustom>; PENDING_LEN], Wrapping>,
    pub fq_deficit: usize,
}

pub enum StateType{
    Rx,
    Tx,
}

impl <'a>State<'a>{
    pub fn new(area: Arc<MmapArea<'a, BufCustom>>, bufs: &mut Vec<BufMmap<'a, BufCustom>>, state_type: StateType, intf: String, map_fd: i32) -> State<'a> {
        let intf = intf.as_str();
        let umem = Umem::new(
            area.clone(),
            4096,
            4096
            //XSK_RING_CONS__DEFAULT_NUM_DESCS,
            //XSK_RING_PROD__DEFAULT_NUM_DESCS,
        );
        let (umem1, cq, mut fq) = match umem {
            Ok(umem) => umem,
            Err(err) => panic!("no umem for you: {:?}", err),
        };
        let mut options = SocketOptions::default();
        options.zero_copy_mode = false;
        options.copy_mode = true;
        
        let (skt, skt_type) = match state_type{
            StateType::Rx => {
                let socket = Socket::new_rx(
                    umem1.clone(),
                    intf,
                    0,
                    //XSK_RING_CONS__DEFAULT_NUM_DESCS,
                    4096,
                    options,
                    1
                );
                let (skt, rx) = match socket {
                    Ok(skt) => skt,
                    Err(err) => panic!("no socket for you: {:?}", err),
                };
                (skt, SocketType::Rx(rx))
            },
            StateType::Tx => {
                let socket = Socket::new_tx(
                    umem1.clone(),
                    intf,
                    0,
                    //XSK_RING_PROD__DEFAULT_NUM_DESCS,
                    4096,
                    options,
                    1
                );
                let (skt, tx) = match socket {
                    Ok(skt) => skt,
                    Err(err) => panic!("no socket for you: {:?}", err),
                };
                (skt, SocketType::Tx(tx))
            },
        };


        let r = fq.fill(
            bufs,
            //min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM),
            4096,
        );
        match r {
            Ok(n) => {
                //if n != min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM) {
                    if n != 4096 {
                    panic!(
                        "Initial fill of umem incomplete. Wanted {} got {}.",
                        BUF_NUM, n
                    );
                }
            }
            Err(err) => panic!("error: {:?}", err),
        }

        let xsk_sock = skt.socket.as_ref() as *const xsk_socket as *mut xsk_socket;        
        unsafe { xsk_socket__update_xskmap(xsk_sock, map_fd) };

        let v: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
        State { cq, fq, socket: skt_type, v, fq_deficit: 0 }

    }
}

pub enum SocketType<'a>{
    Rx(SocketRx<'a, BufCustom>),
    Tx(SocketTx<'a, BufCustom>),
}
