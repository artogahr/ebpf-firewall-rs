#![no_std]
#![no_main]

use aya_ebpf::{helpers::bpf_printk, macros::cgroup_sock_addr, programs::SockAddrContext};

#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    unsafe { bpf_printk!(c"connect4: a process is connecting") };
    1 // 1 = allow the connection, 0 = deny
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
