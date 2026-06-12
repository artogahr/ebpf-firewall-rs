use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // Host-side analysis (rust-analyzer) can't build the eBPF object on a host without
    // bpf-linker (e.g. macOS). With AYA_BUILD_SKIP=1, write an empty stub so the
    // `include_bytes_aligned!` in main.rs resolves and `cargo check` succeeds for editor
    // language features. The real guest build leaves AYA_BUILD_SKIP unset and builds for real.
    if std::env::var_os("AYA_BUILD_SKIP").is_some() {
        let out_dir = std::env::var("OUT_DIR").context("OUT_DIR not set")?;
        std::fs::write(std::path::Path::new(&out_dir).join("firewall"), [])
            .context("writing eBPF stub for AYA_BUILD_SKIP")?;
        return Ok(());
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "firewall-ebpf")
        .ok_or_else(|| anyhow!("firewall-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
