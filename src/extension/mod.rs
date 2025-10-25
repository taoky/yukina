use anyhow::Result;
use clap::ValueEnum;
use std::path::PathBuf;

use crate::{Cli, NormalizedVoteItem};

use self::nix_channels::NixChannels;
pub trait Extension {
    fn name(&self) -> &'static str;
    /// Add related file to download queue based on the downloaded file
    fn parse_downloaded_file(
        &self,
        args: &Cli,
        item: &NormalizedVoteItem,
        client: &reqwest::Client,
    ) -> Result<Option<NormalizedVoteItem>>;
}

pub mod nix_channels;

#[derive(ValueEnum, Debug, Clone)]
pub enum ExtensionType {
    NixChannels,
}

impl ExtensionType {
    pub fn build(&self) -> Box<dyn Extension> {
        match self {
            ExtensionType::NixChannels => Box::<NixChannels>::default(),
        }
    }
}

fn get_target_file_path(args: &Cli, item: &NormalizedVoteItem) -> PathBuf {
    let path = &item.path;
    args.repo_path.join(path)
}
