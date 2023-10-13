use aya::Bpf;
use aya::maps::{HashMap, MapData};
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

const BUFF_SIZE: usize = 2048;
const BUF_NUM: usize = 65535 * 4;
const BATCH_SIZE: usize = 32;
const FILL_THRESHOLD: usize = 32;
const COMPLETION_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS * 32;
const FILL_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS * 32;
const T: u64 = 0;

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
        let mut buffer_counter = 0;
        let mut service_counter: usize = 0;
        let mut sent_counter: usize = 0;
        let mut queue_ring_counter: usize = 0;
        let mut queued_packets = 0;
        let mut service_round: usize = 0;
        let mut buffer_round: usize = 0;
        let mut fill_ring_capacity = FILL_RING_SIZE as usize;
        let mut max_buff = 0;
        let mut received_packet = 0;
        
        loop {
            
            let r = tx_state.cq.service(&mut bufs, BATCH_SIZE);
            let serviced = match r {
                Ok(n) => {
                    if n > 0 {
                        service_counter += n;
                        service_round += 1;
                        fill_ring_capacity += n;
                        buffer_counter -= n;
                        if max_buff < buffer_counter {
                            max_buff = buffer_counter;
                        }
                        warn!("{} packets received. {} packets buffered. Max buffered packets {}. Fill deficit {}. Sent {}. Serviced {}. Queue ring {}.",received_packet, buffer_counter, max_buff, rx_state.fq_deficit, sent_counter, n, queue_ring_counter);
                    }
                    n
                }
                Err(err) => panic!("error: {:?}", err),
            };
            sent_counter = 0;
            received_packet = 0;
            match rx.try_recv(&mut rx_state.v, BATCH_SIZE, custom) {
                Ok(n) => {
                    if n > 0 {
                        received_packet = n;
                        fill_ring_capacity -= n;
                        buffer_counter += n;
                        while let Some(v) = rx_state.v.pop_front(){
                            let data: &[u8] = v.get_data();
                            let data_ptr = data.as_ptr() as usize;
                            let bth_hdr = (data_ptr + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *const BthHdr;
                            let dst_qp = unsafe { (*bth_hdr).dest_qpn };
                            let seq_num = {
                                let seq_num = unsafe { (*bth_hdr).psn_seq };
                                u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]])
                            };
                            queue_ring.insert((dst_qp, seq_num), v);
                        }
                        rx_state.fq_deficit += n;
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
            if queue_ring.len() > 0 && sent_counter == serviced{  
                buffer_round += 1; 
                let mut qp_list = get_qp_list(&mut next_seq_map);
                while let Some((dst_qpn, mut seq)) = qp_list.pop(){
                    let mut k = 0;
                    let mut last_seq = None;
                    let mut buf: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
                    while let Some(v) = queue_ring.remove(&(dst_qpn, seq)){
                        seq += 1;
                        last_seq = Some((dst_qpn, seq));
                        k += 1;
                        buf.push_back(v);
                        if k % BATCH_SIZE == 0 {
                            let p = send(tx, &mut buf).await;
                            sent_counter += p;
                        }
                    }
                    if buf.len() > 0 {
                        let p = send(tx, &mut buf).await;
                        sent_counter += p;
                    }

                    if let Some((dst_qpn, seq)) = last_seq{
                        next_seq_map.insert(dst_qpn, seq, 0)?;
                    }                
                }
                queue_ring_counter = queue_ring.len();
            }
            
            if rx_state.fq_deficit >= BATCH_SIZE {
                let r = rx_state.fq.fill(&mut bufs, rx_state.fq_deficit);
                match r {
                    Ok(n) => {
                        rx_state.fq_deficit -= n;
                    }
                    Err(err) => panic!("error: {:?}", err),
                }
            }
            
        }
        
    }
}

fn get_qp_list(next_seq_map: &mut HashMap<&mut MapData, [u8; 3], u32>) -> Vec<([u8; 3], u32)> {
    let mut qp_list = Vec::new();
    for res in next_seq_map.iter(){
        if let Ok((dst_qpn, seq)) = res {
            qp_list.push((dst_qpn, seq));
        }
    }
    qp_list
}

async fn send<'a>(tx: &mut SocketTx<'a, BufCustom>, v: &mut ArrayDeque<[BufMmap<'a, BufCustom>; PENDING_LEN], Wrapping>) -> usize{
    let p = v.len();
    let mut sent_packets = 0;
    if tx.try_send(v, BATCH_SIZE).is_ok(){
        
        sent_packets = p;
    }
    tokio::time::sleep(tokio::time::Duration::from_micros(T)).await;
    sent_packets
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
            //4096,
            //4096
            COMPLETION_RING_SIZE,
            FILL_RING_SIZE,
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
                    COMPLETION_RING_SIZE,
                    //4096,
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
                    FILL_RING_SIZE,
                    //4096,
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
            min(FILL_RING_SIZE as usize, BUF_NUM),
            //4096,
        );
        match r {
            Ok(n) => {
                if n != min(FILL_RING_SIZE as usize, BUF_NUM) {
                //if n != 4096 {
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
