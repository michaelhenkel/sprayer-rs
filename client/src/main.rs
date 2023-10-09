use tokio::net::UdpSocket;
use std::net::SocketAddr;
use clap::Parser;
use common::BthHdr;
use log::info;
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::fs::File;
use std::io::prelude::*;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Sequence {
    #[serde(rename = "type")]
    sequence_type: BthSeqType,
    id: u32,
    first: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    qp_id: u32,
    sequence: Vec<Sequence>,
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "192.168.1.102:4791")]
    dst: String,
    #[clap(short, long, default_value = "lima1")]
    iface: String,
    #[clap(short, long, default_value = "config.yaml")]
    config: Option<String>,
    #[clap(short, long, default_value = "5")]
    messages: Option<u32>,
    #[clap(short, long, default_value = "5")]
    packets: Option<u32>,
    #[clap(short, long, default_value = "5")]
    qpid: Option<u32>,
    #[clap(short, long, default_value = "100")]
    start: Option<u32>,
}

fn read_yaml_file(file_path: &str) -> Result<Vec<Message>, anyhow::Error> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let messages: Vec<Message> = serde_yaml::from_str(&contents)?;

    Ok(messages)
}

// specified by the iface parameter.
fn get_ip_address_from_interface(iface_name: &str) -> Result<std::net::IpAddr, anyhow::Error> {
    let iface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == iface_name)
        .ok_or(anyhow::anyhow!("interface not found"))?;
    let ip = iface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .ok_or(anyhow::anyhow!("interface has no ipv4 address"))?
        .ip();
    Ok(ip)
}

#[derive(Clone, Debug)]
struct BthSeq{
    messages: Vec<BthHdr>,
    qp_id: [u8;3],
}

impl From<Message> for BthSeq{
    fn from(message: Message) -> Self{
        let qp_id = u32::to_be(message.qp_id);
        let qp_id = qp_id.to_le_bytes();
        println!("qp_id: {:?}", qp_id);
        let mut bth_seq = BthSeq::new([qp_id[1], qp_id[2], qp_id[3]]);
        for sequence in message.sequence{
            bth_seq.add_msg(sequence.sequence_type, sequence.id, false);
        }
        bth_seq
    }
}

impl BthSeq{
    fn new(qp_id: [u8;3]) -> Self{
        Self{
            messages: Vec::new(),
            qp_id,
        }
    }
    fn add_msg(&mut self, bth_seq_type: BthSeqType, seq: u32, first: bool){
        let seq = u32::to_be(seq);
        let seq = seq.to_le_bytes();
        let mut bth_hdr = BthHdr{
            opcode: 1,
            sol_event: 0,
            part_key: 65535,
            //res: if first { 1 } else { 0 },
            res: 0,
            dest_qpn: self.qp_id,
            ack: 0,
            psn_seq: [seq[1], seq[2], seq[3]]
        };
        match bth_seq_type {
            BthSeqType::First => {
                bth_hdr.opcode = 0;
            },
            BthSeqType::Middle => {
                bth_hdr.opcode = 1;
            },
            BthSeqType::Last => {
                bth_hdr.opcode = 2;
                bth_hdr.ack = 128;
            },
        }
        self.messages.push(bth_hdr);
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
enum BthSeqType{
    First,
    Middle,
    Last,
}

fn get_messages(messages: u32, packets: u32, qpid: u32, start: u32) -> Vec<Message>{
    let mut msgs = Vec::new();
    let mut seq_counter = start;
    for i in 0..messages{
        let mut sequence = Vec::new();
        for j in 0..packets{
            
            let sequence_type = if j == 0{
                BthSeqType::First
            } else if j == packets - 1{
                BthSeqType::Last
            } else {
                BthSeqType::Middle
            };
            sequence.push(Sequence{
                sequence_type,
                id: seq_counter,
                first: start == seq_counter,
            });
            seq_counter += 1;
        }
        msgs.push(Message{
            qp_id: qpid,
            sequence,
        });
    }
    msgs
}

#[tokio::main]
async fn main() -> anyhow::Result<()>{
    let opt = Opt::parse();
    let ip = get_ip_address_from_interface(&opt.iface)?;
    let ip_port = format!("{}:{}", ip.to_string(), random_src_port());    
    let sock = UdpSocket::bind(ip_port).await?;
    let remote_addr = opt.dst.parse::<SocketAddr>()?;
    sock.connect(remote_addr).await?;
    let messages = if opt.messages.is_some() && opt.packets.is_some() && opt.qpid.is_some() && opt.start.is_some(){
        get_messages(opt.messages.unwrap(), opt.packets.unwrap(), opt.qpid.unwrap(), opt.start.unwrap())
    } else if let Some(config) = opt.config{
        read_yaml_file(&config)?
    } else {
        panic!("either config or messages, packets, qpid, and start must be specified");
    };
    //let messages = read_yaml_file(&opt.config)?;
    for msg in messages {
        let bth_seq = BthSeq::from(msg);
        for bth_hdr in bth_seq.messages{
            let buf = unsafe {
                let ptr = &bth_hdr as *const BthHdr as *const u8;
                std::slice::from_raw_parts(ptr, std::mem::size_of::<BthHdr>())
            };
            println!("Sending BTH header: {:?}", bth_hdr);
            let mut b = Vec::from(buf);
            let data = String::from("hello");
            let data_bytes = data.as_bytes();
            let c = vec![0;1024];
            let c = c.as_slice();
            b.extend_from_slice(c);
            let b = b.as_slice();
            let _len = sock.send(b).await?;
        }
    }
    Ok(())
}

fn random_src_port() -> u16 {
    rand::random::<u16>()
}


