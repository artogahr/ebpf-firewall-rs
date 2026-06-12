use std::fs::File;
use std::net::Ipv4Addr;

use aya::maps::HashMap;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))?;

    // Each argument is either an IPv4 address (block that destination) or a process
    // name (block that program).
    let mut block_names: Vec<[u8; 16]> = Vec::new();
    let mut block_ips: Vec<u32> = Vec::new();
    for arg in std::env::args().skip(1) {
        if let Ok(ip) = arg.parse::<Ipv4Addr>() {
            block_ips.push(u32::from(ip));
            println!("blocking destination IP: {ip}");
        } else {
            let mut key = [0u8; 16];
            let bytes = arg.as_bytes();
            let n = bytes.len().min(15);
            key[..n].copy_from_slice(&bytes[..n]);
            block_names.push(key);
            println!("blocking process name: {arg}");
        }
    }
    {
        let mut names: HashMap<_, [u8; 16], u8> =
            HashMap::try_from(ebpf.map_mut("BLOCKED_NAMES").unwrap())?;
        for key in &block_names {
            names.insert(key, 0, 0)?;
        }
    }
    {
        let mut ips: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("BLOCKED_IPS").unwrap())?;
        for ip in &block_ips {
            ips.insert(ip, 0, 0)?;
        }
    }

    let cgroup = File::open("/sys/fs/cgroup")?;
    let program: &mut CgroupSockAddr = ebpf.program_mut("connect4").unwrap().try_into()?;
    program.load()?;
    program.attach(&cgroup, CgroupAttachMode::Single)?;

    println!("firewall attached. Press Ctrl-C to exit.");
    signal::ctrl_c().await?;
    Ok(())
}
