#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_printk},
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

// Process names userspace has asked us to block (value unused; membership only).
#[map]
static BLOCKED_NAMES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    let comm = bpf_get_current_comm().unwrap_or_default();

    if unsafe { BLOCKED_NAMES.get(&comm) }.is_some() {
        unsafe { bpf_printk!(c"connect4: %s is blocked (allowing for now)", comm.as_ptr() as u64) };
    }
    1 // still allow; next step turns this into a deny
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
