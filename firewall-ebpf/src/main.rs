#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_printk},
    macros::cgroup_sock_addr,
    programs::SockAddrContext,
};

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // user_ip4 and user_port are in network byte order; convert with from_be.
    let sa = unsafe { &*ctx.sock_addr };
    let dest_ip = u32::from_be(sa.user_ip4);
    let dest_port = u16::from_be(sa.user_port as u16);

    unsafe {
        bpf_printk!(c"connect4: pid %d -> ip %x port %x", pid, dest_ip, dest_port as u32)
    };
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
