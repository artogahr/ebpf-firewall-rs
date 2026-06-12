use std::fs::File;

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

    // Seed the blocklist with the process names passed on the command line.
    let mut names: HashMap<_, [u8; 16], u8> =
        HashMap::try_from(ebpf.map_mut("BLOCKED_NAMES").unwrap())?;
    for arg in std::env::args().skip(1) {
        let mut key = [0u8; 16];
        let bytes = arg.as_bytes();
        let n = bytes.len().min(15);
        key[..n].copy_from_slice(&bytes[..n]);
        names.insert(key, 0, 0)?;
        println!("blocking process name: {arg}");
    }

    let cgroup = File::open("/sys/fs/cgroup")?;
    let program: &mut CgroupSockAddr = ebpf.program_mut("connect4").unwrap().try_into()?;
    program.load()?;
    program.attach(&cgroup, CgroupAttachMode::Single)?;

    println!("firewall attached. Press Ctrl-C to exit.");
    signal::ctrl_c().await?;
    Ok(())
}
