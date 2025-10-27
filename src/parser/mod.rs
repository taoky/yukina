use std::net::IpAddr;

use anyhow::Result;
use chrono::{DateTime, FixedOffset};
use clap::ValueEnum;

pub mod combined;
pub mod mirrorjson;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    Combined,
    MirrorJson,
}

#[derive(Debug)]
pub struct LogItem {
    pub client: IpAddr,
    pub time: DateTime<FixedOffset>,
    pub url: String,
    pub size: u64,
    pub status: u16,
    pub user_agent: String,
    pub proxied: bool,
}

pub trait LogParser {
    fn parse(&self, line: &str) -> Result<LogItem>;
}

pub fn get_log_parser(format: LogFormat) -> Box<dyn LogParser> {
    match format {
        LogFormat::Combined => Box::new(combined::CombinedParser::default()),
        LogFormat::MirrorJson => Box::new(mirrorjson::MirrorJsonParser::default()),
    }
}
