use std::process::Command;

use anyhow::Context;

use super::Extension;

#[derive(Debug, Default)]
pub struct FreeBSDPkg {}

impl Extension for FreeBSDPkg {
    fn name(&self) -> &'static str {
        "freebsd-pkg"
    }

    fn post_process_downloaded_file(
        &self,
        args: &crate::Cli,
        tmp_path: &std::path::Path,
        _target_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        // Create hard link of its sha256sum to .by-hash/

        // 1. Get the sha256sum from the mapping
        let prog = Command::new("sha256sum")
            .arg(tmp_path)
            .output()
            .context("running sha256sum failed")?;
        if !prog.status.success() {
            anyhow::bail!("sha256sum command failed");
        }
        let output = String::from_utf8_lossy(&prog.stdout);
        let parts: Vec<&str> = output.split_whitespace().collect();
        if parts.len() < 2 {
            anyhow::bail!("unexpected sha256sum output");
        }
        let sha256sum = parts[0];

        // 2. Create hard link in .by-hash/
        let by_hash_dir = args.repo_path.join(".by-hash");
        std::fs::create_dir_all(&by_hash_dir)?;
        let link_path = by_hash_dir.join(sha256sum);
        if !link_path.exists() {
            std::fs::hard_link(tmp_path, link_path)?;
        }
        Ok(())
    }
}
