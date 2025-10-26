use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    process::Command,
};

use anyhow::Context;
use serde_json::Value;

use super::Extension;

#[derive(Debug, Default)]
pub struct FreeBSDPkg {
    metadata_path_to_sha256_mapping: HashMap<String, String>,
}

impl Extension for FreeBSDPkg {
    fn name(&self) -> &'static str {
        "freebsd-pkg"
    }

    fn init(&mut self, args: &crate::Cli) -> anyhow::Result<()> {
        let repo_path = &args.repo_path;

        // */*/packagesite.tzst
        for first_level in std::fs::read_dir(repo_path)? {
            let first_level = first_level?;
            if !first_level.file_type()?.is_dir() {
                continue;
            }
            for second_level in std::fs::read_dir(first_level.path())? {
                let second_level = second_level?;
                if !second_level.file_type()?.is_dir() {
                    continue;
                }
                let packagesite_path = second_level.path().join("packagesite.tzst");
                if !packagesite_path.exists() {
                    continue;
                }
                let packagesite_path = packagesite_path.canonicalize()?;
                let status = Command::new("tar")
                    .args([
                        "-C",
                        "/tmp",
                        "--zstd",
                        "-xf",
                        packagesite_path.to_str().unwrap(),
                        "packagesite.yaml",
                    ])
                    .status()
                    .context("running tar failed (are you using GNU tar or not?)")?;

                if !status.success() {
                    anyhow::bail!("tar failed for {:?}", packagesite_path);
                }

                let file = File::open("/tmp/packagesite.yaml")?;
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    let line = line?;
                    let value: Value = serde_json::from_str(&line)?;
                    let hash_value = value["sum"]
                        .as_str()
                        .context("missing 'sum' in JSON line")?;
                    let repopath = value["repopath"]
                        .as_str()
                        .context("missing 'repopath' in JSON line")?;

                    let repopath_full = packagesite_path.parent().unwrap().join(repopath);
                    self.metadata_path_to_sha256_mapping.insert(
                        repopath_full.to_string_lossy().to_string(),
                        hash_value.to_string(),
                    );
                }

                std::fs::remove_file("/tmp/packagesite.yaml")?;
            }
        }

        Ok(())
    }

    fn post_process_downloaded_file(
        &self,
        args: &crate::Cli,
        tmp_path: &std::path::Path,
        target_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        // create hard link of its sha256sum to .by-hash/

        // Get the sha256sum from the mapping
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
        let expected_sha256sum = self
            .metadata_path_to_sha256_mapping
            .get(&target_path.to_string_lossy().to_string())
            .context("missing sha256sum mapping for downloaded file")?;
        if sha256sum != expected_sha256sum {
            anyhow::bail!(
                "sha256sum mismatch for downloaded file ({} != {})",
                sha256sum,
                expected_sha256sum
            );
        }

        // Create hard link in .by-hash/
        let by_hash_dir = args.repo_path.join(".by-hash");
        std::fs::create_dir_all(&by_hash_dir)?;
        let link_path = by_hash_dir.join(sha256sum);
        if !link_path.exists() {
            std::fs::hard_link(tmp_path, link_path)?;
        }
        Ok(())
    }
}
