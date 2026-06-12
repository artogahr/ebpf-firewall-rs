#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_printk},
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

// PIDs userspace has asked us to block. Value is unused (just membership).
#[map]
static BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if unsafe { BLOCKLIST.get(&pid) }.is_some() {
        unsafe { bpf_printk!(c"connect4: pid %d is on the blocklist (allowing for now)", pid) };
    }
    1 // still allow; Step 5 turns this into a deny
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
