# Spike notes (foundation)

Running record of what actually worked on real hardware, so Plans 2 and 3 are
grounded in reality rather than guesses. Append findings under each task.

## Environment as found
- Host: Apple Silicon (arm64), macOS, Determinate Nix 3.20.0 installed, no Lima, no cargo on host.

## Findings

### Task 1: Lima
- Installed via `nix profile install nixpkgs#lima`. Version: limactl 2.1.2 (on PATH).
- Pulls QEMU 11.0.0 + spice/gst deps from cache; uses vz on Apple Silicon.
