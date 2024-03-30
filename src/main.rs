#![warn(clippy::cognitive_complexity)]
use chrono::{DateTime, Utc};
use clap::Parser;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use parse_size::parse_size;
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader},
    net::IpAddr,
    path::PathBuf,
    time::SystemTime,
};
use tracing_subscriber::EnvFilter;
use url::Url;
use yukina::SizeDBItem;

use shadow_rs::shadow;
shadow!(build);

mod combined;
mod term;

fn parse_bytes(s: &str) -> Result<u64, clap::Error> {
    parse_size(s).map_err(|e| clap::Error::raw(clap::error::ErrorKind::ValueValidation, e))
}

#[derive(Parser, Debug)]
#[command(about)]
#[command(propagate_version = true)]
#[command(version = build::SHORT_COMMIT)]
struct Cli {
    /// Repo name, used for finding log file and downloading from remote
    #[clap(long)]
    name: String,

    /// Directory of nginx log
    #[clap(long)]
    log_path: PathBuf,

    /// Directory of repo
    #[clap(long)]
    repo_path: PathBuf,

    /// Don't really download or remove anything, just show what would be done
    #[clap(long)]
    dry_run: bool,

    /// User agent to use
    #[clap(long, default_value = "yukina (https://github.com/taoky/yukina)")]
    user_agent: String,

    /// Size limit of your repo
    #[clap(long, value_parser = parse_bytes)]
    size_limit: u64,

    /// Filter for urls and file paths you interested in (usually blobs of the repo)
    #[clap(long, value_parser)]
    filter: Vec<Regex>,

    /// URL of the remote repo
    #[clap(long)]
    url: Url,

    /// Optional prefix to strip from the path after the repo name
    #[clap(long)]
    strip_prefix: Option<String>,

    /// A kv database of file size to speed up stage3 in case yukina would run frequently
    #[clap(long)]
    size_database: Option<PathBuf>,

    /// Size database Miss TTL
    #[clap(long, default_value = "2d")]
    size_database_ttl: humantime::Duration,

    #[clap(long, value_parser = parse_bytes, default_value = "4g")]
    filesize_limit: u64,
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

fn matches_filter(url: &str, filter: &[Regex]) -> bool {
    if filter.is_empty() {
        return true;
    }
    for re in filter {
        if re.is_match(url) {
            return true;
        }
    }
    false
}

fn relative_uri_normalize(uri: &str) -> String {
    assert!(uri.starts_with('/'));
    let mut url =
        Url::parse(&format!("http://example.com{}", uri)).expect("unexpected url parse failed");
    url.set_query(None);
    url.set_fragment(None);
    let mut path = url.path().to_string();
    // replace duplicated slashes until there is no more
    loop {
        let new_path = path.replace("//", "/");
        if new_path == path {
            break;
        }
        path = new_path;
    }
    path
}

/// URL in UserVote shall not start with `/`: it is relative to the repo root.
type UserVote = Vec<(String, VoteValue)>;
/// normalized by: vote_count / (max(size, 2GB) + 1)
#[derive(Debug, Copy, Clone)]
struct NormalizedFileStats {
    score: f64,
    size: u64,
    exists_local: bool,
}
type NormalizedVote = Vec<(String, NormalizedFileStats)>;

fn normalize_vote(vote_value: &VoteValue, size: u64) -> f64 {
    let vote_count = vote_value.count;
    let size = size.max(2 * 1024 * 1024 * 1024);
    vote_count as f64 / (size.checked_add(1).expect("+1 overflow") as f64 / 1024.0 / 1024.0)
}

/// Paths in the struct are all relative to the repo root
struct FileStats {
    list: Vec<(String, u64)>,
    hm: HashMap<String, u64>,
}

impl FileStats {
    fn new(list: Vec<(String, u64)>) -> Self {
        let hm = list.iter().cloned().collect();
        Self { list, hm }
    }
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

/// Analyse nginx logs and get user votes
fn stage1(args: &Cli) -> UserVote {
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
    // global hit/miss stats
    let mut hit = 0;
    let mut miss = 0;

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
            let path = relative_uri_normalize(&item.url);
            let duration = now_utc.signed_duration_since(item.time);
            if duration.num_hours() > 24 * 7 {
                stop_iterate_flag = true;
                continue;
            }
            if !matches_filter(&path, &args.filter) {
                continue;
            }
            let client_prefix = get_ip_prefix_string(item.client);
            let ip_prefix_url = IpPrefixUrl {
                ip_prefix: client_prefix,
                url: path.clone(),
            };
            if let Some(last_time) = access_record.get(&ip_prefix_url) {
                let delta = item.time.signed_duration_since(*last_time);
                if delta.num_seconds() < 60 * 5 {
                    continue;
                }
            }
            // strip prefix of the path
            let mut path = path
                .strip_prefix(&format!("/{}", args.name))
                .unwrap_or_else(|| panic!("strip prefix failed: {}", path));
            if let Some(prefix) = &args.strip_prefix {
                path = path
                    .strip_prefix(prefix)
                    .expect("unexpected strip prefix failed");
            }
            // path shall not start with `/`
            if path.starts_with('/') {
                path = path.strip_prefix('/').unwrap();
            }
            if path.is_empty() {
                continue;
            }
            let vote = vote.entry(path.to_owned()).or_default();
            vote.count += 1;
            if item.status == 200 {
                vote.success_count += 1;
                hit += 1;
            } else if item.status == 302 || item.status == 404 {
                vote.reject_count += 1;
                miss += 1;
            } else {
                tracing::debug!("Unknown status: {}", item.status);
                vote.unknown_count += 1;
            }
            vote.resp_size = vote.resp_size.max(item.size);
            access_record.insert(ip_prefix_url, item.time.into());
        }
    }

    // Get sorted vote "report". Items with only one vote would be ignored.
    let mut vote: Vec<_> = vote.into_iter().filter(|(_, v)| v.count != 1).collect();
    vote.sort_by_key(|(_, size)| *size);
    vote.reverse();

    let total_size = vote.iter().map(|(_, v)| v.resp_size).sum::<u64>();
    tracing::info!(
        "Got {} votes, total (existing) size {}",
        vote.len(),
        humansize::format_size(total_size, humansize::BINARY)
    );
    tracing::info!(
        "(From nginx log) Hit: {}, Miss: {}, Hit rate: {:.2}%",
        hit,
        miss,
        hit as f64 / (hit + miss) as f64 * 100.0
    );

    vote
}

/// Analyse local files and get metadata of files we are interested in
fn stage2(args: &Cli) -> FileStats {
    let mut res = Vec::new();
    for entry in walkdir::WalkDir::new(&args.repo_path) {
        let entry = entry.expect("walkdir failed");
        // We're not interested in symlinks, etc., and dirs means that we're not in the leaf node
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .strip_prefix(args.repo_path.clone())
            .expect("unexpected strip prefix failed")
            .to_str()
            .expect("unexpected path conversion failed");
        // path shall not start with `/`.
        let path = if path.starts_with('/') {
            path.strip_prefix('/').unwrap()
        } else {
            path
        };
        if !matches_filter(path, &args.filter) {
            continue;
        }
        let file_size = entry.metadata().expect("get metadata failed").len();
        res.push((path.to_string(), file_size));
    }
    res.sort_by_key(|(_, size)| *size);
    res.reverse();

    let total_size = res.iter().map(|(_, size)| *size).sum::<u64>();
    tracing::info!(
        "Got {} files, total size {}",
        res.len(),
        humansize::format_size(total_size, humansize::BINARY)
    );

    FileStats::new(res)
}

pub fn insert_db(db: Option<&sled::Db>, key: &str, size: Option<u64>) {
    if let Some(db) = db {
        let size_item = SizeDBItem {
            size,
            record_time: Utc::now(),
        };
        if let Err(e) = db.insert(key, bincode::serialize(&size_item).unwrap()) {
            tracing::warn!("Size db insert failed: {}", e);
        }
    }
}

/// Get size of non-existing files, and normalize vote value
async fn stage3(
    args: &Cli,
    vote: &UserVote,
    stats: &FileStats,
    client: &reqwest::Client,
    size_db: Option<sled::Db>,
) -> NormalizedVote {
    let mut res = Vec::new();
    let progressbar = progressbar!(Some(vote.len() as u64));
    // Stats counters
    let mut local_hit = 0;
    let mut sizedb_hit = 0;
    let mut sizedb_nonexist = 0;
    let mut remote_hit = 0;
    let mut remote_miss = 0;

    for vote_item in vote {
        progressbar.inc(1);
        let (url_path, vote_value) = vote_item;
        // Check if it exists
        let (size, exists, valid) = if let Some(value) = stats.hm.get(url_path) {
            tracing::debug!("File exists: {} ({})", url_path, value);
            local_hit += 1;
            (*value, true, true)
        } else {
            // if size_db, require sled first
            let mut size_item: Option<SizeDBItem> = None;
            let mut exceeded_miss_ttl = false;
            if let Some(db) = &size_db {
                if let Ok(Some(s)) = db.get(url_path) {
                    if let Ok(s) = bincode::deserialize::<SizeDBItem>(&s) {
                        if s.size.is_none() {
                            let ttl: std::time::Duration = args.size_database_ttl.into();
                            let duration = Utc::now()
                                .signed_duration_since(s.record_time)
                                .to_std()
                                .unwrap_or_default();
                            if duration > ttl {
                                exceeded_miss_ttl = true;
                                let _ = db.remove(url_path);
                            }
                        }
                        size_item = Some(s);
                    }
                }
            }

            // a bit ugly but seems no better solution without nightly rust
            let size_db_condition = size_item.is_some() && !exceeded_miss_ttl;
            if size_db_condition {
                let size_item = size_item.unwrap();
                match size_item.size {
                    Some(size) => {
                        if size == 0 {
                            tracing::warn!("Empty file: {}", url_path);
                        }
                        tracing::debug!(
                            "File does not exist locally: {} (sizedb {})",
                            url_path,
                            size
                        );
                        sizedb_hit += 1;
                        (size, false, true)
                    }
                    None => {
                        tracing::info!("File not found at remote (from sizedb): {}", url_path);
                        sizedb_nonexist += 1;
                        (0, false, false)
                    }
                }
            } else {
                let url = args
                    .url
                    .clone()
                    .join(url_path)
                    .expect("join url failed");
                tracing::debug!("Heading {:?}", url);
                let res = client.head(url).send().await.expect("request failed");
                tracing::debug!("Response: {:?}", res);
                match res.error_for_status() {
                    Ok(res) => {
                        let size = res
                            .headers()
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(0);
                        if size == 0 {
                            tracing::warn!("Empty file: {}", url_path);
                        }
                        tracing::debug!(
                            "File does not exist locally: {} (remote {})",
                            url_path,
                            size
                        );
                        remote_hit += 1;
                        insert_db(size_db.as_ref(), url_path, Some(size));
                        (size, false, true)
                    }
                    Err(e) => {
                        tracing::info!("Invalid file ({}): {}", e, url_path);
                        let is_404 = e.status().map_or(false, |s| s == 404);
                        if is_404 {
                            insert_db(size_db.as_ref(), url_path, None);
                        }
                        remote_miss += 1;
                        (0, false, false)
                    }
                }
            }
        };
        if valid {
            if size > args.filesize_limit {
                tracing::warn!("File too large: {} ({})", url_path, size);
                continue;
            }
            res.push((
                url_path.clone(),
                NormalizedFileStats {
                    score: normalize_vote(vote_value, size),
                    size,
                    exists_local: exists,
                },
            ));
        }
    }
    progressbar.finish();
    tracing::info!(
        "Local hit: {}, SizeDB hit: {}, SizeDB 404: {}, Remote hit: {}, Remote miss: {}",
        local_hit,
        sizedb_hit,
        sizedb_nonexist,
        remote_hit,
        remote_miss
    );
    res
}

/// Generate report (for now)
async fn stage4(args: &Cli, normalized_vote: &NormalizedVote, stats: &FileStats) {
    let mut sum = stats.list.iter().map(|(_, size)| *size).sum::<u64>();
    let max = args.size_limit;

    // Two "queues". We take items from tail.
    let mut to_download_queue: Vec<_> = normalized_vote
        .iter()
        .filter(|x| !x.1.exists_local)
        .collect();
    // sorted score small -> large, filesize large -> small (taking large score first)
    to_download_queue.sort_by(|a, b| match a.1.score.partial_cmp(&b.1.score).unwrap() {
        std::cmp::Ordering::Equal => b.1.size.cmp(&a.1.size),
        std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
        std::cmp::Ordering::Less => std::cmp::Ordering::Less,
    });
    let mut to_remove_queue: Vec<_> = normalized_vote
        .iter()
        .filter(|x| x.1.exists_local)
        .cloned()
        .collect();
    // for files get no votes, add to to_remove_queue with 0 score
    {
        let to_remove_hs: HashSet<_> = to_remove_queue.iter().map(|x| x.0.clone()).collect();
        for item in stats.list.clone() {
            if !to_remove_hs.contains(&item.0) {
                to_remove_queue.push((
                    item.0,
                    NormalizedFileStats {
                        score: 0.0,
                        size: item.1,
                        exists_local: true,
                    },
                ));
            }
        }
    }
    // sorted score large -> small, filesize large -> small (taking small score first)
    to_remove_queue.sort_by(|a, b| match b.1.score.partial_cmp(&a.1.score).unwrap() {
        std::cmp::Ordering::Equal => a.1.size.cmp(&b.1.size),
        std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
        std::cmp::Ordering::Less => std::cmp::Ordering::Less,
    });

    while sum > max {
        // well, it's too large even don't get anything
        // just remove!
        let local_item = to_remove_queue
            .pop()
            .expect("Nothing to remove while size exceeds");
        // TODO: remove local file
        tracing::info!("Remove: {:?}", local_item);
        sum -= local_item.1.size;
    }

    while let Some(item) = to_download_queue.pop() {
        // does size fit?
        let remote_score = item.1.score;
        let remote_size = item.1.size;
        if sum.checked_add(remote_size).unwrap() <= max {
            // TODO: download
            tracing::info!("Download: {:?}", item);
            sum += remote_size;
        } else if sum <= max {
            // well, we have to remove something, or stop the process
            let mut stop_flag = false;
            while sum.checked_add(remote_size).unwrap() > max {
                let local_item = to_remove_queue.pop();
                let local_item = match local_item {
                    None => {
                        // file too large? skip this one
                        tracing::info!("Skipped {:?} as it's too large", item);
                        continue;
                    }
                    Some(l) => l,
                };
                // Compare score, if the file to download is even less popular than local one, stop.
                let local_size = local_item.1.size;
                let local_score = local_item.1.score;
                if local_score >= remote_score {
                    tracing::info!("Stopped downloading/removing.");
                    stop_flag = true;
                    break;
                }
                // TODO: remove local file
                tracing::info!("Remove: {:?}", local_item);
                sum -= local_size;
            }
            if stop_flag {
                break;
            }
            // TODO: download remote file
            tracing::info!("Download: {:?}", item);
            sum += remote_size;
        } else {
            unreachable!("sum > max");
        }
    }
}

#[tokio::main]
async fn main() {
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

    // Print version info in debug mode
    tracing::debug!("{}", build::CLAP_LONG_VERSION);

    let bind_address = match std::env::var("BIND_ADDRESS").ok() {
        Some(s) => {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                Some(s.to_owned())
            }
        }
        None => None,
    };

    let args = Cli::parse();
    tracing::debug!("{:?}", args);

    let client = reqwest::Client::builder()
        .user_agent(&args.user_agent)
        .redirect(reqwest::redirect::Policy::default())
        .local_address(bind_address.map(|s| s.parse().expect("parse bind address failed")))
        .build()
        .expect("build client failed");

    let size_db = if let Some(sd_path) = &args.size_database {
        let db = sled::open(sd_path);
        let db = match db {
            Ok(db) => db,
            Err(e) => {
                tracing::warn!("Open size database failed: {}", e);
                tracing::warn!("Remove and try again...");
                let _ = std::fs::remove_file(sd_path);
                sled::open(sd_path).expect("open failed when tried again")
            }
        };
        tracing::info!("Size database opened: {:?}", sd_path);
        Some(db)
    } else {
        None
    };

    // change cwd
    std::env::set_current_dir(&args.repo_path).expect("change cwd failed");

    let vote = stage1(&args);
    let stats = stage2(&args);
    let normalized_vote = stage3(&args, &vote, &stats, &client, size_db).await;
    stage4(&args, &normalized_vote, &stats).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relative_uri_normalize() {
        assert_eq!(
            relative_uri_normalize("/test/a/../test?aaa=bbb&ccc=ddd#aaaaa"),
            "/test/test"
        );
        assert_eq!(relative_uri_normalize("/test////abc"), "/test/abc")
    }
}
