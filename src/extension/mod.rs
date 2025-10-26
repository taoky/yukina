use anyhow::Result;
use clap::ValueEnum;
use std::path::{Path, PathBuf};

use crate::{Cli, NormalizedVoteItem};

use self::nix_channels::NixChannels;
pub trait Extension {
    fn name(&self) -> &'static str;
    fn init(&mut self, _args: &Cli) -> Result<()> {
        Ok(())
    }
    /// Add related file to download queue based on the downloaded file
    fn parse_downloaded_file(
        &self,
        _args: &Cli,
        _item: &NormalizedVoteItem,
        _client: &reqwest::Client,
    ) -> Result<Option<NormalizedVoteItem>> {
        Ok(None)
    }
    /// Code to run after downloaded and before being renamed to final path
    fn post_process_downloaded_file(&self, _args: &Cli, _tmp_path: &Path) -> Result<()> {
        Ok(())
    }
}

pub mod freebsd_pkg;
pub mod nix_channels;

#[derive(ValueEnum, Debug, Clone)]
pub enum ExtensionType {
    NixChannels,
    FreebsdPkg,
}

impl ExtensionType {
    pub fn build(&self, args: &Cli) -> Box<dyn Extension> {
        let mut obj: Box<dyn Extension> = match self {
            ExtensionType::NixChannels => Box::<NixChannels>::default(),
            ExtensionType::FreebsdPkg => Box::<freebsd_pkg::FreeBSDPkg>::default(),
        };
        obj.init(args).unwrap();
        obj
    }
}

fn get_target_file_path(args: &Cli, item: &NormalizedVoteItem) -> PathBuf {
    let path = &item.path;
    args.repo_path.join(path)
}
