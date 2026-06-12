#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_printk},
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

#[map]
static BLOCKED_NAMES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

#[map]
static BLOCKED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    // Block by WHO: the process name.
    let comm = bpf_get_current_comm().unwrap_or_default();
    if unsafe { BLOCKED_NAMES.get(&comm) }.is_some() {
        unsafe { bpf_printk!(c"connect4: BLOCKING name %s", comm.as_ptr() as u64) };
        return 0;
    }

    // Block by WHERE: the destination IP.
    let sa = unsafe { &*ctx.sock_addr };
    let dest_ip = u32::from_be(sa.user_ip4);
    if unsafe { BLOCKED_IPS.get(&dest_ip) }.is_some() {
        unsafe { bpf_printk!(c"connect4: BLOCKING ip %x", dest_ip) };
        return 0;
    }

    1 // allow
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
