# Workshop Docs and CI Implementation Plan (Plan 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add presenter support and quality scaffolding: instructor notes (agenda, per-step talking points, the demo technique, a real verifier-tripping example, the optional LAN cache), and CI that builds every step branch so no broken checkpoint ships.

**Architecture:** Two deliverables. (1) `docs/instructor-notes.md`, a single readable document the presenter uses to run the session. (2) A GitHub Actions workflow that, on a Linux runner with Nix, builds each step branch with the flake's guest dev shell. No VM is needed in CI: a Linux runner builds the eBPF natively via the flake, unlike participant Macs.

**Tech Stack:** Markdown docs; GitHub Actions + DeterminateSystems Nix installer; the existing flake `.#guest` shell (nightly + LLVM-22 bpf-linker). All work that touches the build happens on the `workshop` Lima guest, as in Plans 1 and 2.

**Builds on Plans 1 and 2 (both complete and verified).** Proven facts in `docs/spike-notes.md`: guest boots with `nix run .#start`; build `nix develop -c cargo build --locked`; run `RUST_LOG=info cargo run`; trace pipe `/sys/kernel/tracing/trace_pipe`; deny = EPERM; branches `main`, `step-1`..`step-6` (+ tags `step-0`, `solution`). Demo technique: block a shell's own PID via `: <>/dev/tcp/HOST/PORT`.

---

## Task 1: Find and verify a real verifier-tripping example

The spec's verifier segment needs code that actually makes the kernel verifier reject the program on this guest (kernel 7.0.10). Plan 2 found the natural Step 3 code did NOT trip it, so we must find a real rejection and capture its exact message. Do this on a scratch branch; do not keep it in a step branch.

**Files:**
- Temporary: `firewall-ebpf/src/main.rs` on a throwaway branch `scratch-verifier`.

- [ ] **Step 1: Create a scratch branch from step-1**

```bash
git switch step-1 && git switch -c scratch-verifier
```

- [ ] **Step 2: Try candidate A - an unbounded loop over a runtime bound**

Replace the `connect4` body in `firewall-ebpf/src/main.rs` with a loop the verifier cannot prove terminates:

```rust
#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    let n = (aya_ebpf::helpers::bpf_get_current_pid_tgid() & 0xffff) as u64;
    let mut acc: u64 = 0;
    let mut i: u64 = 0;
    while i < n {
        acc = acc.wrapping_add(i);
        i += 1;
    }
    unsafe { bpf_printk!(c"acc=%lld", acc) };
    1
}
```
Build and load:
```bash
nix develop -c cargo build --locked
nix develop -c bash -c 'cargo run --locked'
```
Expected: the loader prints a verifier error at `program.load()` (something like `BpfProgramError` / "back-edge" / "infinite loop detected" / instruction-limit). Capture the EXACT error text.

- [ ] **Step 3: If candidate A loads cleanly, try candidate B - oversized stack**

If A did not trip the verifier, replace the body with a large stack array:

```rust
#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    let buf = [0u8; 1024]; // BPF stack is 512 bytes
    unsafe { bpf_printk!(c"first=%d", buf[0] as u32) };
    1
}
```
Build and load as in Step 2. Capture whether this fails at `bpf-linker` (build) or the kernel verifier (load), and the exact message.

- [ ] **Step 4: Record the working example**

Append to `docs/spike-notes.md` under a "Verifier example" heading: which candidate trips the verifier on kernel 7.0.10, the exact error message, and whether it fails at load (verifier) or link (bpf-linker). This is the source of truth for the instructor notes.

- [ ] **Step 5: Delete the scratch branch**

```bash
git switch main
git branch -D scratch-verifier
```
(The verified snippet lives in instructor notes, not in a branch.)

---

## Task 2: Write the instructor notes

**Files:**
- Create: `docs/instructor-notes.md`

- [ ] **Step 1: Write `docs/instructor-notes.md`**

Create the file with the full content below. Replace the `VERIFIER EXAMPLE` block's snippet and error text with the real one recorded in Task 1 Step 4 before committing.

````markdown
# Instructor Notes

Presenter guide for the eBPF + Rust firewall workshop. Participant-facing setup is in
the top-level `README.md`; this file is for running the session.

## Before the day

- Tell participants to do the README "Setup" section as homework: install Nix
  (Determinate), clone the repo, run `nix run .#start` once on good internet (the image
  is a few GB), then the Step 0 check. This warms their guest so the room is not pulling
  gigabytes over shared wifi.
- Bring the repo on a USB stick as a fallback for anyone who did not clone it.

## Optional: local Nix cache for a crowd

If many people did not warm their cache at home, serve the closure over the room LAN so
they pull at LAN speed instead of from the internet. On your laptop, from the repo:

```bash
# Simplest: serve your local /nix/store read-only over HTTP.
nix run nixpkgs#nix-serve -- --port 5000
```
Participants then add your laptop as a substituter for one command:
```bash
nix develop --option substituters "http://<your-laptop-ip>:5000 https://cache.nixos.org" \
            --option trusted-public-keys "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
```
Note: `nix-serve` serves unsigned paths; participants must pass
`--option require-sigs false` if they do not trust-configure your key. Test this on one
machine before relying on it for the room.

## Timing (120-minute slot)

| Segment | Time | Branch |
|---|---|---|
| Setup check + the big picture | 15 min | `main` |
| Step 1: catch the hook | 10 min | `step-1` |
| Step 2: read the PID | 10 min | `step-2` |
| Step 3: read the destination | 15 min | `step-3` |
| Step 4: maps, log before enforce | 25 min | `step-4` |
| Step 5: the kill switch | 15 min | `step-5` |
| Step 6 + the verifier | 15 min | `step-6` |
| Buffer / questions | 15 min | |

Flex: drop to 60 min by demoing Steps 1-3 instead of live-coding them; extend to 180 min
by adding the TC packet-drop stretch (see the design spec).

## How to live-code each step

You start each step on the previous branch and type only the small diff. If you fall
behind or a demo breaks, `git switch step-N` to jump to a known-good checkpoint. The
hand-typed delta per step is only a few lines; everything else is already there.

## The demo that works: block a shell's own PID

A `curl` forks a child with a fresh PID every run, so you cannot pre-block it. Instead
block a shell's OWN PID and have that shell connect via bash's `/dev/tcp`:

```bash
# In a guest shell:
echo $$                              # this shell's PID, e.g. 1234
: <>/dev/tcp/1.1.1.1/80 && echo ok   # the shell itself calls connect()
```
Then run the firewall blocking that PID (from another guest shell, in the repo):
```bash
nix develop -c bash -c 'cargo run --locked -- 1234'
```
Back in the first shell, `: <>/dev/tcp/1.1.1.1/80` now fails with
`Operation not permitted` (EPERM). A different shell (different PID) still connects.

## Per-step talking points

- **Step 0 (hello):** two ways to see kernel output. aya-log routes through your own
  loader (a perf buffer, a preview of maps). `bpf_printk` writes to the kernel's global
  trace pipe (`sudo cat /sys/kernel/tracing/trace_pipe`). Same program, two windows.
- **Step 1 (catch the hook):** `cgroup/connect4` runs inside the `connect()` syscall for
  every process in the cgroup. Returning 1 allows, 0 denies. We attach to the root
  cgroup so it sees everything.
- **Step 2 (PID):** `bpf_get_current_pid_tgid()` packs tgid (the "PID" users see) in the
  high 32 bits; `>> 32` extracts it. This is the process identity the kernel normally
  loses when moving packets.
- **Step 3 (destination):** the target is in the program context (`bpf_sock_addr`).
  `user_ip4` and `user_port` are network byte order, hence `from_be`. Good moment to show
  decoding `1010101` hex back to `1.1.1.1`.
- **Step 4 (maps, log before enforce):** a `HashMap` is shared memory between your app
  and the kernel. The loader writes PIDs; the kernel reads them. We deliberately only LOG
  here, proving the two sides talk before we let the kernel block anything.
- **Step 5 (kill switch):** the entire firewall is one returned value. `return 0` turns
  the log into a denial. Show curl/`/dev/tcp` failing with EPERM, then a different PID
  still working.
- **Step 6 (IPv6):** a connect4-only firewall is silently bypassed by IPv6 apps. The
  `connect6` hook shares the same blocklist. The hook runs before routing, so even with
  no IPv6 route the denial shows as EPERM rather than "network unreachable".

## The verifier segment

The verifier checks every path terminates and every memory access is in bounds, before
the program is allowed to load. The natural workshop code passes cleanly, so to SHOW the
verifier rejecting something, paste this into `connect4` and try to load it:

<!-- VERIFIER EXAMPLE: replace with the snippet + exact error verified in Task 1 -->
```rust
// (verified verifier-tripping snippet goes here)
```
Expected rejection (captured on kernel 7.0.10):
```
(exact verifier error text goes here)
```
Talking points: the error appears at load time (`program.load()`), not at compile time;
the verifier is the kernel protecting itself from your code; the trace logs and the
verifier log are your two debugging tools.

## Troubleshooting

- **`bpf-linker` "Invalid record":** the toolchain LLVM and bpf-linker's LLVM differ. The
  flake pins them together (`llvmPackagesForLinker = llvmPackages_22`); rebuild the dev
  shell. See `docs/spike-notes.md`.
- **Permission denied loading the program:** the loader must run as root. `cargo run`
  already wraps in `sudo -E` via `.cargo/config.toml`.
- **No trace output:** read the pipe as root: `sudo cat /sys/kernel/tracing/trace_pipe`.
- **A step branch misbehaves:** `git switch step-N` for a known-good checkpoint; CI builds
  every branch so they should always compile.
````

- [ ] **Step 2: Commit**

```bash
git add docs/instructor-notes.md docs/spike-notes.md
git commit -m "docs: instructor notes (agenda, talking points, demo, verifier example)"
```

---

## Task 3: Add CI that builds every step branch

A Linux runner builds the eBPF natively via the flake (no VM needed), so CI can verify
that every checkpoint branch compiles. This is what makes the homework path trustworthy.

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: ci
on:
  push:
    branches: ["main", "step-*"]
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        branch: [main, step-1, step-2, step-3, step-4, step-5, step-6]
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ matrix.branch }}
      - uses: DeterminateSystems/nix-installer-action@main
      - uses: DeterminateSystems/magic-nix-cache-action@main
      - name: Build the workspace with the guest dev shell
        run: nix develop .#guest --command cargo build --locked
```

- [ ] **Step 2: Validate the workflow file locally**

We cannot run GitHub Actions here, but we can sanity-check it. Confirm the branch matrix
matches the real branches:
```bash
git branch --format='%(refname:short)' | sort
```
Expected: `main`, `step-1` .. `step-6` all present (the matrix lists `main` and
`step-1`..`step-6`).

- [ ] **Step 3: Confirm the build command works on a branch (proxy for CI)**

CI runs `nix develop .#guest --command cargo build --locked`. We have already proven this
on the aarch64 guest for every branch in Plan 2. Re-confirm once on `main` inside the
guest as a proxy (x86_64 runners exercise the same flake outputs):
```bash
limactl shell workshop -- sh -c 'nix --extra-experimental-features "nix-command flakes" develop .#guest --command cargo build --locked 2>&1' | tail -2
```
Expected: `Finished` line. Note in `docs/spike-notes.md` that x86_64 CI is unverified
locally (only aarch64 hardware available) but uses the same flake `.#guest` output.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml docs/spike-notes.md
git commit -m "ci: build every step branch with the flake guest shell"
```

- [ ] **Step 5: Propagate CI and instructor-notes pointer to the step branches (optional but recommended)**

The workflow and instructor notes live on `main`. For CI to run on pushes to the step
branches, cherry-pick the CI commit onto each:
```bash
CI_COMMIT=$(git rev-parse HEAD~1)   # the ci.yml commit if it is the prior commit; adjust as needed
for b in step-1 step-2 step-3 step-4 step-5 step-6; do
  git switch "$b" && git cherry-pick -x "$CI_COMMIT"
done
git switch main
```
If a cherry-pick conflicts (it should not, `.github/` is new), resolve by taking the new
file. Verify each branch now has `.github/workflows/ci.yml`. Re-tag `solution` if step-6
moved: `git tag -f solution step-6`.

---

## Task 4: Final review and return to main

**Files:** none (verification).

- [ ] **Step 1: Confirm the tree and branches**

```bash
git switch main
git status --short        # expect clean
ls docs/instructor-notes.md .github/workflows/ci.yml
```
Expected: clean tree; both files exist on main.

- [ ] **Step 2: Record completion**

Append a "Plan 3 complete" line to `docs/spike-notes.md` noting the verifier example
found, that CI builds all branches, and any cherry-pick results.

```bash
git add docs/spike-notes.md
git commit -m "docs: plan 3 complete (instructor notes + CI)"
```

---

## Self-Review (completed by plan author)

**Spec coverage:** Implements the spec's remaining items: instructor notes with timing,
talking points, homework, and the optional `harmonia`/`nix-serve` LAN cache (Task 2); the
verifier teaching segment, now backed by a real tested rejection rather than the natural
code that does not trip it (Task 1 feeding Task 2); and the CI build matrix over every
step branch (Task 3), which the spec's "Testing" section calls for. The behavior smoke
test from the spec is intentionally downgraded to the per-branch compile check plus the
manual in-guest verification already done in Plan 2, because GitHub-hosted runners cannot
reliably nest virtualization to load eBPF; this is stated, not silently dropped.

**Placeholder scan:** The only intentional placeholder is the `VERIFIER EXAMPLE` block in
Task 2, which is explicitly filled from the value Task 1 verifies on real hardware before
committing. Every command and the CI YAML are concrete.

**Consistency:** Branch names (`main`, `step-1`..`step-6`), tags (`step-0`, `solution`),
the build command (`nix develop .#guest --command cargo build --locked`), and the run
command (`cargo run` with the `sudo -E` runner) match Plans 1 and 2 and `docs/spike-notes.md`.
