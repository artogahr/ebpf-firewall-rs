#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_printk},
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

#[map]
static BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Shared decision for both IPv4 and IPv6 connect attempts.
fn decide() -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { BLOCKLIST.get(&pid) }.is_some() {
        unsafe { bpf_printk!(c"connect: BLOCKING pid %d", pid) };
        return 0; // deny
    }
    1 // allow
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    decide()
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(_ctx: SockAddrContext) -> i32 {
    decide()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
