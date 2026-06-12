# Instructor Notes

Presenter guide for the eBPF + Rust firewall workshop. Participant-facing setup is in
the top-level `README.md`; this file is for running the session.

The firewall blocks outbound connections by **who** (process name) and **where**
(destination IP), decided in the kernel at the `connect()` syscall. Two block criteria,
built one after the other.

## Before the day

- Tell participants to do the README "Setup" section as homework: install Nix
  (Determinate), clone the repo, `nix run .#start` once on good internet (the image is a
  few GB), then the Step 0 check. This warms their guest so the room is not pulling
  gigabytes over shared wifi.
- Bring the repo on a USB stick as a fallback for anyone who did not clone it.

## Optional: local Nix cache for a crowd

If many people did not warm their cache at home, serve the closure over the room LAN so
they pull at LAN speed instead of from the internet. On your laptop, from the repo:

```bash
nix run nixpkgs#nix-serve -- --port 5000
```
Participants add your laptop as a substituter for one command:
```bash
nix develop --option substituters "http://<your-laptop-ip>:5000 https://cache.nixos.org" \
            --option require-sigs false
```
Test it on one machine before relying on it for the room.

## Timing (120-minute slot)

| Segment | Time | Branch |
|---|---|---|
| Setup check + the big picture | 15 min | `main` |
| Step 1: catch the hook | 8 min | `step-1` |
| Step 2: read who (process name) | 8 min | `step-2` |
| Step 3: read where (destination) | 12 min | `step-3` |
| Step 4: maps, log before enforce | 20 min | `step-4` |
| Step 5: kill switch by name | 12 min | `step-5` |
| Step 6: kill switch by destination | 12 min | `step-6` |
| Step 7: IPv6 + the verifier | 8 + 12 min | `step-7` |
| Buffer / questions | ~13 min | |

Flex: drop to 60 min by demoing instead of live-coding steps 1-3; extend to 180 min by
adding the TC packet-drop / per-app redirect stretch (what the full `lockne` project does,
via a socket-cookie bridge).

## How to live-code each step

Start each step on the previous branch and type only the small diff (below). If you fall
behind or a demo breaks, `git switch step-N` jumps to a known-good checkpoint. Build and
run from inside the guest:

```bash
nix run .#enter                          # shell into the guest, already in the dev shell
cargo build                              # build
cargo run -- curl                        # block the program named "curl"
cargo run -- 1.1.1.1                     # block the destination 1.1.1.1
cargo run -- curl 1.1.1.1                # block both
```
`cargo run` auto-elevates via `runner = "sudo -E"`. Keep a second `nix run .#enter` shell
for `sudo cat /sys/kernel/tracing/trace_pipe`.

## The demo that works (no PID gymnastics)

Because the firewall matches on the process **name** and the destination **IP**, you just
run it and watch: no PIDs, no `/dev/tcp`, any terminal.

**Block by name:**
```bash
cargo run -- curl            # in the loader shell
# in another shell:
curl 1.1.1.1                 # FAILS (Operation not permitted)
nc -z 1.1.1.1 80             # SUCCEEDS (nc is a different program)
```
**Block by destination:**
```bash
cargo run -- 1.1.1.1
curl 1.1.1.1                 # FAILS
curl 1.0.0.1                 # SUCCEEDS (different IP; both are Cloudflare web servers)
```
Demo targets: **1.1.1.1** and **1.0.0.1** both serve HTTP, so "blocked vs allowed" is a
clean exit-7-vs-exit-0 contrast. Avoid 8.8.8.8 (DNS only, no HTTP; it times out and looks
ambiguous). Contrast program: **nc** (installed in the guest); `wget`/`python3` are not.

## Live-coding cheat: the exact delta per step

Full source of each step is on its branch (`git show step-N:firewall-ebpf/src/main.rs`).
Files: eBPF is `firewall-ebpf/src/main.rs`, loader is `firewall/src/main.rs`.

**Step 1 (from Step 0): tracepoint -> connect4.** Bigger change; consider pasting the
loader. eBPF:
```rust
use aya_ebpf::{helpers::bpf_printk, macros::cgroup_sock_addr, programs::SockAddrContext};

#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    unsafe { bpf_printk!(c"connect4: a process is connecting") };
    1 // 1 = allow, 0 = deny
}
```
Loader: load the program, `File::open("/sys/fs/cgroup")`, attach `CgroupSockAddr` with
`CgroupAttachMode::Single`, wait for Ctrl-C. (See `step-1:firewall/src/main.rs`.)

**Step 2 (eBPF only): read who.** Add `bpf_get_current_comm` to the imports, then:
```rust
    let comm = bpf_get_current_comm().unwrap_or_default();
    unsafe { bpf_printk!(c"connect4: %s is connecting", comm.as_ptr() as u64) };
```
(`%s` reads the process name from the comm buffer; pass the pointer as `u64`.)

**Step 3 (eBPF only): read where.** Rename `_ctx` to `ctx`, then:
```rust
    let sa = unsafe { &*ctx.sock_addr };
    let dest_ip = u32::from_be(sa.user_ip4);
    let dest_port = u16::from_be(sa.user_port as u16);
    unsafe { bpf_printk!(c"connect4: %s -> ip %x port %d", comm.as_ptr() as u64, dest_ip, dest_port as u32) };
```

**Step 4: the name map (eBPF) + seed it (loader).** eBPF: add `macros::map`,
`maps::HashMap`, then:
```rust
#[map]
static BLOCKED_NAMES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);
// in connect4:
    if unsafe { BLOCKED_NAMES.get(&comm) }.is_some() {
        unsafe { bpf_printk!(c"connect4: %s is blocked (allowing for now)", comm.as_ptr() as u64) };
    }
```
Loader: add `use aya::maps::HashMap;` and seed from argv (a name padded to 16 bytes):
```rust
    let mut names: HashMap<_, [u8; 16], u8> = HashMap::try_from(ebpf.map_mut("BLOCKED_NAMES").unwrap())?;
    for arg in std::env::args().skip(1) {
        let mut key = [0u8; 16];
        let b = arg.as_bytes();
        let n = b.len().min(15);
        key[..n].copy_from_slice(&b[..n]);
        names.insert(key, 0, 0)?;
        println!("blocking process name: {arg}");
    }
```

**Step 5 (eBPF only): kill switch by name.** Change the `if` body to deny:
```rust
    if unsafe { BLOCKED_NAMES.get(&comm) }.is_some() {
        unsafe { bpf_printk!(c"connect4: BLOCKING %s", comm.as_ptr() as u64) };
        return 0;
    }
```

**Step 6: kill switch by destination.** eBPF: add a second map and an IP check after the
name check:
```rust
#[map]
static BLOCKED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);
// in connect4, after the name check:
    let sa = unsafe { &*ctx.sock_addr };
    let dest_ip = u32::from_be(sa.user_ip4);
    if unsafe { BLOCKED_IPS.get(&dest_ip) }.is_some() {
        unsafe { bpf_printk!(c"connect4: BLOCKING ip %x", dest_ip) };
        return 0;
    }
```
Loader: route each argument: an IPv4 address goes to `BLOCKED_IPS`, anything else is a
name (see `step-6:firewall/src/main.rs`): `arg.parse::<Ipv4Addr>()` -> `u32::from(ip)`.

**Step 7: IPv6.** eBPF: pull the name check into a shared `name_blocked()` and add a
`connect6` hook that calls it:
```rust
fn name_blocked() -> bool {
    let comm = bpf_get_current_comm().unwrap_or_default();
    if unsafe { BLOCKED_NAMES.get(&comm) }.is_some() {
        unsafe { bpf_printk!(c"connect: BLOCKING name %s", comm.as_ptr() as u64) };
        return true;
    }
    false
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(_ctx: SockAddrContext) -> i32 {
    if name_blocked() { return 0; }
    1
}
```
Loader: after the connect4 attach, load+attach `connect6` to the same cgroup.

## Per-step talking points

- **Step 0 (hello):** `bpf_printk` writes to the kernel trace pipe
  (`sudo cat /sys/kernel/tracing/trace_pipe`); every command fires it via `execve`.
  (Aside: aya-log is a nicer library logger that routes to your own app; we use the trace
  pipe throughout for one simple mechanism.)
- **Step 1 (catch the hook):** `cgroup/connect4` runs inside the `connect()` syscall for
  every process in the cgroup. Return 1 = allow, 0 = deny. We attach to the root cgroup so
  it sees everything.
- **Step 2 (who):** `bpf_get_current_comm()` is the process name the kernel already knows.
  This is the identity an IP-based firewall throws away.
- **Step 3 (where):** the destination is in the program context (`bpf_sock_addr`), in
  network byte order, hence `from_be`. `1010101` hex decodes to 1.1.1.1; port `80`.
- **Step 4 (maps, log before enforce):** a `HashMap` is shared memory between your app and
  the kernel. The loader writes names; the kernel reads them. We deliberately only LOG
  here, proving the two sides talk before we let the kernel block anything. Note `get`
  returns an `Option`: the verifier makes you handle "not found".
- **Step 5 (block by who):** the whole firewall is one returned value. `block curl` and
  curl can't reach the network from any shell, while `nc` still can. Selective, by
  identity, in the kernel.
- **Step 6 (block by where):** a second map, a second criterion. Now you can say "nothing
  reaches 1.1.1.1" regardless of which program. Who and where are the two questions a
  firewall asks.
- **Step 7 (IPv6):** a connect4-only firewall is silently bypassed by IPv6 apps. The
  `connect6` hook shares the same name logic. It runs before routing, so even with no IPv6
  route the denial is EPERM ("Operation not permitted"), not "network unreachable".

## The verifier segment

The verifier checks every path terminates and every memory access is in bounds before the
program loads. The natural workshop code passes cleanly (kernel 7.0.10's verifier even
handles bounded loops), so to SHOW a rejection, paste this genuine infinite loop into
`connect4` and try to load it:

```rust
#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    loop {
        unsafe { bpf_printk!(c"spinning forever") };
    }
}
```
It compiles and links fine. The rejection happens at LOAD time:
```
infinite loop detected at insn 4
processed 12 insns (limit 1000000) ...

Caused by:
    Invalid argument (os error 22)
```
Talking points: the error is at load (`program.load()`), not compile time; the verifier is
the kernel protecting itself; the register/instruction dump plus the trace pipe are your
debugging tools.

## Troubleshooting

- **`bpf-linker` "Invalid record":** toolchain LLVM and bpf-linker's LLVM differ. The
  flake pins them together (`llvmPackagesForLinker = llvmPackages_22`); rebuild the shell.
- **Permission denied loading the program:** must run as root. `cargo run` already wraps
  in `sudo -E`.
- **No trace output:** read the pipe as root: `sudo cat /sys/kernel/tracing/trace_pipe`.
- **`error: toolchain 'nightly-...' is not installed`:** something put `rustup` on PATH.
  The Nix guest has none; if one leaked in, remove it (`rustup self uninstall -y`).
- **Name block does nothing:** the kernel `comm` is the binary name truncated to 15 chars
  (e.g. `curl`). Block exactly that. A `curl` launched via a wrapper script has the
  wrapper's name, not `curl`.
- **A step branch misbehaves:** `git switch step-N` for a known-good checkpoint; CI builds
  every branch.
