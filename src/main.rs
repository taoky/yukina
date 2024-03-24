use chrono::{DateTime, Utc};
use clap::Parser;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use parse_size::parse_size;
use regex::Regex;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    net::IpAddr,
    path::PathBuf,
    time::SystemTime,
};
use tracing_subscriber::EnvFilter;

mod combined;

fn parse_bytes(s: &str) -> Result<u64, clap::Error> {
    parse_size(s).map_err(|e| clap::Error::raw(clap::error::ErrorKind::ValueValidation, e))
}

#[derive(Parser, Debug)]
struct Cli {
    #[clap(long)]
    name: String,

    #[clap(long)]
    log_path: PathBuf,

    #[clap(long)]
    repo_path: PathBuf,

    #[clap(long)]
    dry_run: bool,

    #[clap(long, default_value = "yukina")]
    user_agent: String,

    #[clap(long, value_parser = parse_bytes)]
    size_limit: u64,

    #[clap(long, value_parser)]
    filter: Vec<Regex>,
}

enum LogFileType {
    Plain,
    Gzip,
    Zstd,
    Xz,
}

fn deduce_log_file_type(filename: &str) -> LogFileType {
    if filename.ends_with(".gz") {
        LogFileType::Gzip
    } else if filename.ends_with(".zst") {
        LogFileType::Zstd
    } else if filename.ends_with(".xz") {
        LogFileType::Xz
    } else {
        LogFileType::Plain
    }
}

fn get_ip_prefix_string(ip: IpAddr) -> String {
    let client_prefix = match ip {
        IpAddr::V4(ipv4) => {
            // Assuming a /24 prefix for IPv4
            IpNetwork::V4(Ipv4Network::new(ipv4, 24).unwrap())
        }
        IpAddr::V6(ipv6) => {
            // Assuming a /48 prefix for IPv6
            IpNetwork::V6(Ipv6Network::new(ipv6, 48).unwrap())
        }
    };
    client_prefix.to_string()
}

#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
struct VoteValue {
    count: u64,
    success_count: u64,
    reject_count: u64,
    unknown_count: u64,
    resp_size: u64,
}

impl PartialOrd for VoteValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VoteValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.count.cmp(&other.count)
    }
}

fn stage1(args: &Cli) {
    let mut entries: Vec<_> = std::fs::read_dir(&args.log_path)
        .expect("read log path failed")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_type().ok().map_or(false, |ft| ft.is_file())
                && entry
                    .file_name()
                    .to_str()
                    .map_or(false, |s| s.starts_with(&format!("{}.log", args.name)))
        })
        .collect();
    entries.sort_by_cached_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    entries.reverse();

    tracing::debug!("Entries: {:?}", entries);

    let now_utc = chrono::Utc::now();
    let combined_parser = combined::CombinedParser::default();

    #[derive(Debug, Eq, PartialEq, Hash)]
    struct IpPrefixUrl {
        ip_prefix: String,
        url: String,
    }

    let mut access_record: HashMap<IpPrefixUrl, DateTime<Utc>> = HashMap::new();
    let mut vote: HashMap<String, VoteValue> = HashMap::new();

    let mut stop_iterate_flag = false;
    for entry in entries {
        if stop_iterate_flag {
            tracing::info!(
                "Would not process {} due to time limit",
                entry.path().display()
            );
            break;
        }
        let filename = entry.file_name();
        let filename = filename.to_str().unwrap();
        // decide whether directly read the file, or use a decompressor
        let filetype = deduce_log_file_type(filename);
        let bufreader: BufReader<Box<dyn std::io::Read>> = match filetype {
            LogFileType::Plain => {
                let file = std::fs::File::open(entry.path()).expect("open file failed");
                std::io::BufReader::new(Box::new(file))
            }
            _ => {
                let prog = match filetype {
                    LogFileType::Gzip => "zcat",
                    LogFileType::Zstd => "zstdcat",
                    LogFileType::Xz => "xzcat",
                    _ => unreachable!(),
                };
                let output = std::process::Command::new(prog)
                    .arg(entry.path())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("spawn decompressor failed");
                std::io::BufReader::new(Box::new(output.stdout.expect("get stdout failed")))
            }
        };

        for line in bufreader.lines() {
            let line = line.expect("read line failed");
            let item = combined_parser.parse(&line).expect("parse line failed");
            let url = &item.url;
            let duration = now_utc.signed_duration_since(item.time);
            if duration.num_hours() > 24 * 7 {
                stop_iterate_flag = true;
                continue;
            }
            // if filter is not empty, only process the matched url
            let mut matched = args.filter.is_empty();
            for re in &args.filter {
                if re.is_match(url) {
                    matched = true;
                }
            }
            if !matched {
                continue;
            }
            let client_prefix = get_ip_prefix_string(item.client);
            let ip_prefix_url = IpPrefixUrl {
                ip_prefix: client_prefix,
                url: url.clone(),
            };
            if let Some(last_time) = access_record.get(&ip_prefix_url) {
                let delta = item.time.signed_duration_since(*last_time);
                if delta.num_seconds() < 60 * 5 {
                    continue;
                }
            }
            let vote = vote.entry(url.clone()).or_default();
            vote.count += 1;
            if item.status == 200 {
                vote.success_count += 1;
            } else if item.status == 302 || item.status == 404 {
                vote.reject_count += 1;
            } else {
                tracing::debug!("Unknown status: {}", item.status);
                vote.unknown_count += 1;
            }
            vote.resp_size = vote.resp_size.max(item.size);
            access_record.insert(ip_prefix_url, item.time.into());
        }
    }

    // Print vote "report" for now
    let mut vote: Vec<_> = vote.into_iter().collect();
    vote.sort_by_key(|(_, size)| *size);
    vote.reverse();
    for (url, value) in vote {
        if value.count == 1 {
            break;
        }
        println!("{}: {:?}", url, value);
    }
}

fn main() {
    std::env::set_var(
        "RUST_LOG",
        format!("info,{}", std::env::var("RUST_LOG").unwrap_or_default()),
    );
    let enable_color = std::env::var("NO_COLOR").is_err();
    tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env())
        .with_ansi(enable_color)
        .init();

    let args = Cli::parse();
    tracing::debug!("{:?}", args);

    stage1(&args);
}
