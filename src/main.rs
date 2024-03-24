use clap::Parser;
use parse_size::parse_size;
use regex::Regex;
use std::{
    io::{BufRead, BufReader},
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

    for entry in entries {
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
            let item = combined::combined_parse(&line).expect("parse line failed");
            let url = &item.url;
            for re in &args.filter {
                if !re.is_match(url) {
                    continue;
                }
            }
            println!("{:?}", item)
        }
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
