# eBPF + Rust Firewall Workshop — Design

**Date:** 2026-06-12
**Author:** Arto Gahr
**Status:** Approved design (pending spec review)

## Purpose

Workshop materials for *"Accessing the Linux kernel using eBPF and Rust"* — a
120-minute advanced workshop (flexible to 60/180). Participants build a working
process-identity firewall: the Linux kernel allows or denies network connections
based on which process initiated them, with state shared between a Rust userspace
app and the kernel.

The materials must let a mixed audience — **mostly Apple Silicon MacBooks**, some
Linux — go from zero to a working eBPF program inside a ~15-minute setup window,
and complete the core build in **~90 minutes**.

**Pedagogical principle (drives the whole structure):** the value is the *path*, not
the final artifact. The firewall is built as a ladder of small, individually
runnable/observable steps, each introducing exactly one new concept, so participants
understand how they arrived at the end product. Guiding arc:
**see the hook fire → read data → store data → enforce.** Observe before you act.

## Core constraint that shapes everything

**eBPF only exists in the Linux kernel. macOS has no eBPF subsystem.** Nix gives
every participant an identical *build* environment but cannot give a Mac a kernel
to *load* programs into. Therefore the actual execution target is a Linux VM, and
that VM's kernel is pinned so the verifier behaves identically for all participants
(critical for the verifier teaching — one shared experience, not 30 unique
debugging sessions).

## Environment & distribution

- **Ship a git flake, not a disk image.** The repo is kilobytes; the environment is
  reconstructed from `flake.lock` against `cache.nixos.org`, byte-identical for all.
- **One Lima + NixOS guest for everyone** (Mac and Linux alike). A single
  `workshop.yaml` Lima config runs on both macOS and Linux hosts and auto-selects
  `aarch64-linux` / `x86_64-linux`. The guest is **NixOS with the kernel pinned in
  the flake** (BTF enabled, cgroup v2, eBPF-relevant kernel config).
- **All `nix` work happens inside the guest**, sidestepping the "can't build Linux
  derivations from Darwin" trap (no `linux-builder` needed on participant Macs).
- **Homework:** participants run `limactl start` once at home to warm the guest's
  `/nix/store` over good internet.
- **Day-of bandwidth safety net:** the instructor's laptop runs a local Nix binary
  cache (`harmonia`) on the workshop LAN; participants add it as a substituter, so
  closure pulls happen at LAN speed and offline — independent of venue wifi. This is
  the single highest-leverage defense against a setup-time disaster.

## Tooling

- **Aya** (pure Rust on both kernel and userspace sides — no C, no libbpf, no kernel
  headers), scaffolded from `aya-template` via `cargo-generate`.
- Rust nightly + `bpf-linker` provided by the flake devShell (inside the guest).
- Cargo workspace:
  - `firewall-ebpf` — the kernel program(s).
  - `firewall` — userspace loader + CLI (push a PID onto the blocklist).
  - `firewall-common` — shared types between kernel and userspace.

## Workshop content — the iterative step ladder (90-min core)

The core firewall uses a **single program type**: a `cgroup/connect4` (plus a
`connect6` one-liner) hook. Returning `0` from this hook denies the `connect()`
syscall in-kernel — no TC, no skb parsing, no socket-cookie bridge.

Each step is a **checkpoint branch** participants can land on if they fall behind.

| Step | New concept | What they write | What they observe | Likely verifier moment |
|---|---|---|---|---|
| **0 — Hello eBPF** *(setup check)* | the load→attach→trace loop; toolchain works | a trivial program that fires and logs | a line in the trace pipe | "compiled but won't load" — first taste |
| **1 — Catch the hook** | program types; attaching to `cgroup/connect4` | hook that logs `"connect fired"` on every connect | run `curl`, watch the log fire | — |
| **2 — Read context: PID** | kernel context + helpers (`bpf_get_current_pid_tgid`) | add PID to the log | two terminals → two different PIDs | — |
| **3 — Read more: dest IP/port** | reading the program context struct; endianness | parse sockaddr, log destination | log shows *who* → *where* | byte-order / bounds gotcha |
| **4 — Share state: maps** | BPF maps + userspace loader + `common` crate | `HashMap` blocklist; CLI pushes a PID; kernel **logs** "PID X is blocked" *(no enforce yet)* | add PID via CLI → kernel notices it | map lookup returns `Option` — verifier insists you handle it |
| **5 — The kill switch** | return value controls kernel behavior | flip step 4's log into `return 0` (deny) | `curl` in blocked shell fails | — |
| **6 — (buffer) `connect6` + CLI polish** | IPv6 bypass; ergonomics | one-liner `connect6`; nicer CLI | IPv6 app also blocked | — |

### Why the ladder is shaped this way

- **Step 4 deliberately stops at "log, don't enforce."** This is the pedagogical
  hinge: participants prove kernel and userspace are *talking* (identity flows in,
  kernel reacts) before any blocking happens. Step 5 is then a one-line change from
  "log it" to "deny it", so the kill switch feels earned, not magic.
- **The verifier is not bolted on at the end.** It ambushes participants naturally at
  steps 0, 3, and 4, so the closing segment *consolidates* scars they already have
  rather than introducing the concept cold.

### Rough timing

Step 0 inside the 15-min setup check; Steps 1–2 ~10 min each; Step 3 ~15; Step 4 ~25
(the big one); Step 5 ~15; Step 6 + verifier consolidation (~15) in the remaining
buffer. Core build ≈ 90 min, plus 15 setup + 15 verifier ≈ the 120-min slot.

### Honest framing notes (to state plainly during the workshop)

- This blocks at **connect time**, not per-packet: existing open connections are not
  torn down; the firewall denies *new* connections from a blocked app. An easy, honest
  thing to explain and a natural lead-in to *why* one would reach for TC.
- It is IPv4 via `connect4`; `connect6` is added (Step 6) so IPv6-capable apps don't
  silently bypass the rule and confuse participants.
- The guest is headless, so the demo is **"watch `curl` stop"** (run from inside the
  VM), not "watch your browser stop." Same effect, accurate to the setup.

## Optional stretch / 180-min extension: TC packet drop

The original proposal's TC packet-drop version is preserved as bonus content. It uses
a socket-cookie bridge: the `connect4` hook records the blocked socket's cookie
(`bpf_get_socket_cookie`) into a map; a TC egress program looks up
`bpf_get_socket_cookie(skb)` per packet and returns `TC_ACT_SHOT` to drop. This is the
per-packet version and the content for the longer workshop variant.

## Teaching scaffolding (so stragglers survive)

- Git **checkpoint branches** matching the ladder: `step-0` … `step-5` (and
  `step-6`/`solution`). Anyone who falls behind checks out the next step and rejoins.
- The `hello-world` eBPF program for the setup-check segment (Step 0).
- Participant `README` with the staged tasks, plus separate instructor notes (local
  cache setup, homework instructions, timing, talking points).

## Verifying the materials before the day

- CI builds the flake + guest closure for **both arches** (`aarch64-linux`,
  `x86_64-linux`) so the homework path is trustworthy.
- A lightweight smoke test: boot the VM, load `hello-world`, assert trace output
  appears. (Trimmable if CI runners can't nest virtualization, but recommended.)

## Components summary / boundaries

| Unit | Purpose | Depends on |
|------|---------|-----------|
| `flake.nix` | devShell, pinned NixOS guest config, kernel pin, harmonia cache | nixpkgs (pinned) |
| `workshop.yaml` | Lima config booting the NixOS guest, mounts repo | Lima, flake |
| `firewall-ebpf` | `cgroup/connect4(+6)` hook | aya-ebpf, `firewall-common` |
| `firewall` | userspace loader + CLI to manage blocklist map | aya, `firewall-common` |
| `firewall-common` | shared map key/value types | (none) |
| checkpoint branches | per-step catch-up points | git |
| `README` + instructor notes | participant + instructor guidance | (docs) |
| CI | both-arch build + optional boot smoke test | flake |

## Out of scope (YAGNI)

- A "full" firewall (rule persistence, config files, allowlists, logging UI).
- Per-packet TC dropping in the core path (moved to optional stretch).
- Supporting native Linux host execution as a separate path (everyone uses the VM).
- Shipping prebuilt disk-image blobs (flake + cache reconstruction instead).
