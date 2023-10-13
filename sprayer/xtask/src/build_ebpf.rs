use std::{path::PathBuf, process::Command};

use clap::Parser;

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
    /// Build the release target
    #[clap(long)]
    pub release: bool,
}

pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {

    //let tc_dir = PathBuf::from("tc-egress-ebpf");
    //let xdp_dir = PathBuf::from("xdp-ingress-ebpf");
    let xdp_encap_dir = PathBuf::from("xdp-encap-ebpf");
    let xdp_decap_dir = PathBuf::from("xdp-decap-ebpf");
    let xdp_dummy_dir = PathBuf::from("xdp-dummy-ebpf");
    let xdp_peer_disco_dir = PathBuf::from("xdp-peer-disco-ebpf");

    let target = format!("--target={}", opts.target);
    let mut args = vec![
        "build",
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];
    if opts.release {
        args.push("--release")
    }

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.

    /*
    let tc_status = Command::new("cargo")
        .current_dir(tc_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build tc bpf program");
    assert!(tc_status.success());

    let xdp_status = Command::new("cargo")
        .current_dir(xdp_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build xdp bpf program");
    assert!(xdp_status.success());
    */

    let xdp_encap_status = Command::new("cargo")
        .current_dir(xdp_encap_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build xdp encap bpf program");
    assert!(xdp_encap_status.success());

    let xdp_decap_status = Command::new("cargo")
        .current_dir(xdp_decap_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build xdp decap bpf program");
    assert!(xdp_decap_status.success());

    let xdp_dummy_status = Command::new("cargo")
        .current_dir(xdp_dummy_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build xdp dummy bpf program");
    assert!(xdp_dummy_status.success());

    let xdp_peer_disco_status = Command::new("cargo")
        .current_dir(xdp_peer_disco_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build xdp peer disco bpf program");
    assert!(xdp_peer_disco_status.success());
    
    Ok(())
}
