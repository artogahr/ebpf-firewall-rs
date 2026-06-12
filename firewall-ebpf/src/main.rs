#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_printk},
    macros::cgroup_sock_addr,
    programs::SockAddrContext,
};

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    let comm = bpf_get_current_comm().unwrap_or_default();

    // The connect target lives in the program context, in network byte order.
    let sa = unsafe { &*ctx.sock_addr };
    let dest_ip = u32::from_be(sa.user_ip4);
    let dest_port = u16::from_be(sa.user_port as u16);

    unsafe {
        bpf_printk!(
            c"connect4: %s -> ip %x port %d",
            comm.as_ptr() as u64,
            dest_ip,
            dest_port as u32
        )
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
