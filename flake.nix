{
  description = "eBPF + Rust firewall workshop";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    nixos-lima.url = "github:nixos-lima/nixos-lima";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      nixos-lima,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # aya-template generates no rust-toolchain.toml. The eBPF crate is built via
        # aya-build's cargo-in-cargo step which needs `-Z build-std`, so a nightly
        # toolchain with rust-src is required. selectLatestNightlyWith is reproducible
        # once flake.lock pins rust-overlay.
        rustNightly = pkgs.rust-bin.selectLatestNightlyWith (
          toolchain:
          toolchain.default.override {
            # rust-analyzer is bundled so editors connected to the guest (e.g. VS Code
            # Remote-SSH) get autocomplete and type-checking. Host-native analysis is
            # impossible here: aya (userspace) is Linux-only and the eBPF crate targets
            # bpfel, so neither crate can `cargo check` on macOS.
            extensions = [
              "rust-src"
              "rustfmt"
              "clippy"
              "rust-analyzer"
            ];
          }
        );

        # bpf-linker reads the LLVM bitcode that rustc emits, so it MUST be built
        # against the same LLVM major version as the nightly toolchain. The nixpkgs
        # default bpf-linker links LLVM 21, but the current nightly bundles LLVM 22,
        # which produces "ERROR llvm: Invalid record" at link time. Pin bpf-linker to
        # LLVM 22 to match. (If a future nightly bumps to LLVM 23, bump this too.)
        bpfLinker = pkgs.bpf-linker.override { llvmPackagesForLinker = pkgs.llvmPackages_22; };

        # Host shell (laptop, macOS or Linux): the tools to launch the guest.
        hostShell = pkgs.mkShell {
          packages = [ pkgs.lima ];
          shellHook = ''
            echo "Host shell ready. Boot the workshop guest with:"
            echo "  nix run .#start   (or: limactl start ./workshop.yaml)"
          '';
        };

        # Guest shell (inside the Linux VM): the full eBPF/Rust toolchain, used to BUILD.
        guestShell = pkgs.mkShell {
          packages = [
            rustNightly
            bpfLinker
            pkgs.llvmPackages_22.clang
            pkgs.pkg-config
          ];
        };

        # Host editing shell: rust + rust-src + rust-analyzer, no bpf-linker. The project
        # can't be built on a non-Linux host, but it CAN be analyzed/cross-checked, so this
        # gives editor language features. Builds instantly on macOS (no LLVM/bpf-linker).
        analyzerShell = pkgs.mkShell { packages = [ rustNightly ]; };
      in
      {
        # `nix develop` does the right thing per platform: on macOS (a host) you get the
        # editing toolchain; on Linux (the guest, or a Linux laptop) you get the full build
        # toolchain. So a plain `nix develop` works everywhere with no flags.
        devShells = {
          default = if pkgs.stdenv.isDarwin then analyzerShell else guestShell;
          guest = guestShell; # force the full build toolchain anywhere
          analyzer = analyzerShell;
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
          host = hostShell; # lima only, for booting the guest manually
        };

        # VM lifecycle as flake apps — Lima is macOS-only (it boots Linux VMs), so
        # these apps are only exposed on Darwin. On Linux you are already in the guest.
        #   nix run .#start    boot the guest
        #   nix run .#enter    shell into the guest
        #   nix run .#stop     stop the guest
        apps = pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
          start = {
            type = "app";
            program = toString (
              pkgs.writeShellScript "start" ''
                # Lima instances are global (~/.lima), not per-clone. If a "workshop"
                # instance already exists, start it instead of trying to recreate it.
                if ${pkgs.lima}/bin/limactl list -q 2>/dev/null | grep -qx workshop; then
                  ${pkgs.lima}/bin/limactl start workshop "$@" 2>/dev/null \
                    || echo "Guest 'workshop' is already running. Shell in with: nix run .#enter"
                else
                  ${pkgs.lima}/bin/limactl start --name=workshop ./workshop.yaml "$@"
                fi
              ''
            );
          };
          enter = {
            type = "app";
            program = toString (
              pkgs.writeShellScript "enter" ''
                # Drop straight into the dev shell inside the guest, so cargo and the
                # toolchain are ready immediately (no separate `nix develop` step).
                # sudo and curl stay on PATH, so this shell works for building, running,
                # reading the trace pipe, and triggering connections.
                exec ${pkgs.lima}/bin/limactl shell workshop -- nix develop "$@"
              ''
            );
          };
          stop = {
            type = "app";
            program = toString (
              pkgs.writeShellScript "stop" ''
                exec ${pkgs.lima}/bin/limactl stop workshop "$@"
              ''
            );
          };
        };
      }
    );
}
