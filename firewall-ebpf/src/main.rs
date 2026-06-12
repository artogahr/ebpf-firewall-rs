#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_printk},
    macros::cgroup_sock_addr,
    programs::SockAddrContext,
};

#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    // The name of the process making the connection (e.g. "curl").
    let comm = bpf_get_current_comm().unwrap_or_default();
    unsafe { bpf_printk!(c"connect4: %s is connecting", comm.as_ptr() as u64) };
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
