#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_printk},
    macros::cgroup_sock_addr,
    programs::SockAddrContext,
};

#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    unsafe { bpf_printk!(c"connect4: pid %d is connecting", pid) };
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
