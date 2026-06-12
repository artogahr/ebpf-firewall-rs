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

    // Seed the blocklist with the PIDs passed on the command line.
    let mut blocklist: HashMap<_, u32, u8> =
        HashMap::try_from(ebpf.map_mut("BLOCKLIST").unwrap())?;
    for arg in std::env::args().skip(1) {
        let pid: u32 = arg.parse()?;
        blocklist.insert(pid, 0, 0)?;
        println!("blocking PID {pid}");
    }

    // Attach to the root cgroup v2, so the hook sees every process on the system.
    let cgroup = File::open("/sys/fs/cgroup")?;
    let program: &mut CgroupSockAddr = ebpf.program_mut("connect4").unwrap().try_into()?;
    program.load()?;
    program.attach(&cgroup, CgroupAttachMode::Single)?;

    println!("firewall attached. Press Ctrl-C to exit.");
    signal::ctrl_c().await?;
    Ok(())
}
