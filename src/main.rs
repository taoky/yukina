#![warn(clippy::cognitive_complexity)]
use anyhow::Result;
use bar::get_progress_bar;
use chrono::Utc;
use clap::Parser;
use futures_util::{stream::StreamExt, Future};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use parse_size::parse_size;
use regex::Regex;
use std::{
    collections::HashMap,
    fs::create_dir_all,
    io::Write,
    net::IpAddr,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};
use tracing::{level_filters::LevelFilter, warn};
use tracing_subscriber::EnvFilter;
use url::Url;
use yukina::{db_remove, db_set, RemoteSizeDBItem};

use shadow_rs::shadow;
shadow!(build);

mod bar;
mod extension;
mod parser;
mod stages;

use stages::*;

use crate::parser::LogFormat;

fn parse_bytes(s: &str) -> Result<u64, clap::Error> {
    parse_size(s).map_err(|e| clap::Error::raw(clap::error::ErrorKind::ValueValidation, e))
}

#[allow(clippy::const_is_empty)]
fn get_version() -> &'static str {
    let tag = build::TAG;
    let clean = build::GIT_CLEAN;
    let short_commit = build::SHORT_COMMIT;
    if !clean {
        Box::leak(format!("{} (dirty)", build::SHORT_COMMIT).into_boxed_str())
    } else if tag.is_empty() {
        if short_commit.is_empty() {
            build::PKG_VERSION
        } else {
            short_commit
        }
    } else {
        tag
    }
}

#[derive(Parser, Debug)]
#[command(about)]
#[command(propagate_version = true)]
#[command(version = get_version())]
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

    /// Don't really download or remove anything, just show what would be done. (HEAD requests are still sent.)
    #[clap(long)]
    dry_run: bool,

    /// Log items to check. Access log beyond log_duration would be ignored
    #[clap(long, default_value = "7d")]
    log_duration: humantime::Duration,

    /// User agent to use
    #[clap(long, default_value = "yukina (https://github.com/taoky/yukina)")]
    user_agent: String,

    /// Size limit of your repo
    #[clap(long, value_parser = parse_bytes)]
    size_limit: u64,

    /// Filter for urls and file paths you interested in (usually blobs of the repo). Relative to repo_path.
    #[clap(long, value_parser)]
    filter: Vec<Regex>,

    /// URL of the remote repo. Still need to give any URL (would not be used) when --gc-only is set.
    #[clap(long)]
    url: Url,

    /// Optional prefix to strip from the path after the repo name. Access URLs must match strip_prefix if set.
    #[clap(long)]
    strip_prefix: Option<String>,

    /// A kv database of file size to speed up stage3 in case yukina would run frequently
    #[clap(long)]
    remote_sizedb: Option<PathBuf>,

    /// Another kv database of file size, but for local files, to skip lstat()s
    #[clap(long)]
    local_sizedb: Option<PathBuf>,

    /// Size database Miss TTL
    #[clap(long, default_value = "2d")]
    size_database_ttl: humantime::Duration,

    /// Single file size limit, files larger than this will NOT be counted/downloaded
    #[clap(long, value_parser = parse_bytes, default_value = "4g")]
    filesize_limit: u64,

    /// Minimum vote count to consider a file as a candicate.
    #[clap(long, default_value_t = 2)]
    min_vote_count: u64,

    /// Retry count for each request.
    #[clap(long, default_value_t = 3)]
    retry: usize,

    /// Extension for specific repo types
    #[clap(long, value_enum)]
    extension: Option<extension::ExtensionType>,

    /// Aggressively remove all files not accessed during log_duration, instead of just keep it within threshold.
    #[clap(long)]
    aggressive_removal: bool,

    /// Don't download anything, just remove unpopular files.
    #[clap(long)]
    gc_only: bool,

    /// Error threshold for download. If the number of download errors exceeds this threshold, yukina will exit with error code 1.
    /// Setting this to 0 will disable this early exit behavior.
    #[clap(long, default_value_t = 5)]
    download_error_threshold: usize,

    /// Format of the log file
    /// If not set, use combined log format (the default of nginx)
    #[clap(long, value_enum, default_value_t = LogFormat::Combined)]
    log_format: LogFormat,
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

fn log_uri_normalize(uri: &str) -> Result<String> {
    let mut url = {
        if uri.starts_with("http:") || uri.starts_with("https:") {
            Url::parse(uri)?
        } else {
            if !uri.starts_with('/') {
                return Err(anyhow::anyhow!("relative uri should start with /: {}", uri));
            }
            Url::parse(&format!("http://example.com{}", uri))?
        }
    };
    url.set_query(None);
    url.set_fragment(None);
    let path = url.path().to_string();
    let mut path = percent_encoding::percent_decode_str(&path)
        .decode_utf8()?
        .to_string();
    // replace duplicated slashes until there is no more
    loop {
        let new_path = path.replace("//", "/");
        if new_path == path {
            break;
        }
        path = new_path;
    }
    Ok(path)
}

/// URL in UserVote shall not start with `/`: it is relative to the repo root.
type UserVote = Vec<(String, VoteValue)>;
/// normalized by: vote_count / (max(size, 2GB) + 1)
#[derive(Debug, Copy, Clone)]
struct NormalizedFileStats {
    score: f64,
    original_score: u64,
    size: u64,
    exists_local: bool,
}

#[derive(Debug, Clone)]
struct NormalizedVoteItem {
    path: String,
    stats: NormalizedFileStats,
}
type NormalizedVote = Vec<NormalizedVoteItem>;

impl PartialEq for NormalizedVoteItem {
    fn eq(&self, other: &Self) -> bool {
        self.stats.score == other.stats.score && self.stats.size == other.stats.size
    }
}

impl Eq for NormalizedVoteItem {}

impl PartialOrd for NormalizedVoteItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NormalizedVoteItem {
    /// Greater -> More priority
    /// Larger score -> More priority
    /// Eq score, smaller size -> More priority
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.stats.score == other.stats.score {
            other.stats.size.cmp(&self.stats.size)
        } else {
            self.stats.score.partial_cmp(&other.stats.score).unwrap()
        }
    }
}

fn normalize_vote(vote_count: u64, size: u64) -> f64 {
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

fn insert_remotedb(db: Option<&sled::Db>, key: &str, size: Option<u64>) {
    if let Some(db) = db {
        let size_item = RemoteSizeDBItem {
            size,
            record_time: Utc::now(),
        };
        if let Err(e) = db_set::<RemoteSizeDBItem>(Some(db), key, size_item) {
            tracing::warn!("Size db insert failed: {}", e);
        }
    }
}

fn construct_url(args: &Cli, url_path: &str) -> Url {
    args.url.clone().join(url_path).expect("join url failed")
}

async fn again<T, Fut, F: Fn() -> Fut>(f: F, retry: usize) -> Result<T>
where
    Fut: Future<Output = Result<T>>,
{
    let mut count = 0;
    loop {
        match f().await {
            Ok(x) => return Ok(x),
            Err(e) => {
                tracing::warn!("Error: {:?}, retrying {}/{}", e, count, retry);
                count += 1;
                if count > retry {
                    return Err(e);
                }
            }
        }
    }
}

fn remove_file(
    args: &Cli,
    item: &NormalizedVoteItem,
    local_db: Option<&sled::Db>,
) -> Result<(), std::io::Error> {
    let path = &item.path;
    let full_path = args.repo_path.join(path);
    if args.dry_run {
        tracing::info!("Would remove: {:?}", full_path);
        return Ok(());
    }
    if let Err(e) = std::fs::remove_file(&full_path) {
        tracing::warn!("Remove file failed: {:?}", e);
        return Err(e);
    }

    tracing::info!("Removed: {:?} (score = {})", full_path, item.stats.score);
    if let Err(e) = db_remove(local_db, path) {
        tracing::warn!("Remove from local db failed: {:?}", e);
    }

    Ok(())
}

async fn head_file(args: &Cli, url: &str, client: &reqwest::Client) -> Result<reqwest::Response> {
    match again(|| async { Ok(client.head(url).send().await?) }, args.retry).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            tracing::warn!("Head failed: {}", e);
            Err(e)
        }
    }
}

/// Returns actual size of the file. When used with dry_run, returns 0.
async fn download_file(
    args: &Cli,
    item: &NormalizedVoteItem,
    client: &reqwest::Client,
    extension: &Option<Box<dyn crate::extension::Extension>>,
) -> Result<usize> {
    if item.stats.exists_local {
        tracing::warn!("item is marked as exists_local, skipping download");
        return Ok(item.stats.size as usize);
    }
    let path = &item.path;
    // Precheck if file already exists
    let filepath = args.repo_path.join(path);
    if filepath.exists() {
        tracing::warn!(
            "File {:?} is requested to download but already exists locally. Not downloading.",
            filepath
        );
        return Ok(filepath.metadata().unwrap().len() as usize);
    }
    let url = construct_url(args, path);
    if args.dry_run {
        tracing::info!("Would download: {} -> {:?}", url, args.repo_path.join(path));
        return Ok(0);
    }
    tracing::info!("Downloading {} (score = {})", url, item.stats.score);
    async fn download(
        args: &Cli,
        path: &str,
        url: &str,
        client: &reqwest::Client,
        extension: &Option<Box<dyn crate::extension::Extension>>,
    ) -> Result<usize> {
        let resp = client.get(url).send().await?.error_for_status()?;
        let total_size = resp.content_length();
        let progressbar = get_progress_bar(
            total_size.unwrap_or(0),
            &format!("Downloading: {}", url),
            Some("{msg}\n[{elapsed_precise}] {state_emoji} {bytes}/{total_bytes} ({bytes_per_sec}, {eta})"),
        );

        // Try to get mtime from response headers
        fn get_response_mtime(resp: &reqwest::Response) -> Option<chrono::DateTime<Utc>> {
            let headers = resp.headers();
            let mtime = headers.get("Last-Modified")?;
            let mtime = mtime.to_str().ok()?;
            let mtime = chrono::DateTime::parse_from_rfc2822(mtime)
                .ok()?
                .with_timezone(&Utc);
            Some(mtime)
        }
        let mtime = get_response_mtime(&resp);

        let tmp_path = args.repo_path.join(format!("{}.tmp", path));
        // Make sure tmp_path has parent folder created
        let tmp_parent = tmp_path.parent().unwrap();
        if let Err(e) = create_dir_all(tmp_parent) {
            warn!("create dir {:?} failed with {}", tmp_parent, e);
        }
        {
            let mut dest_file = std::fs::File::create(&tmp_path)?;
            let mut stream = resp.bytes_stream();

            while let Some(item) = stream.next().await {
                let chunk = item?;
                dest_file.write_all(&chunk)?;
                progressbar.inc(chunk.len() as u64);
                if let Some(mtime) = mtime {
                    let _ = filetime::set_file_handle_times(
                        &dest_file,
                        None,
                        Some(filetime::FileTime::from_system_time(mtime.into())),
                    );
                }
            }
        }
        let target_path = args.repo_path.join(path);
        if let Some(ext) = extension {
            if let Err(e) = ext.post_process_downloaded_file(args, &tmp_path) {
                tracing::warn!("Post-process downloaded file failed: {}", e);
                std::fs::remove_file(&tmp_path)?;
                return Err(e);
            }
        }
        std::fs::rename(&tmp_path, &target_path)?;
        Ok(std::fs::metadata(&target_path)?.len() as usize)
    }
    match again(
        || download(args, path, url.as_str(), client, extension),
        args.retry,
    )
    .await
    {
        Ok(filesize) => {
            tracing::info!("Downloaded: {} -> {:?}", url, args.repo_path.join(path));
            Ok(filesize)
        }
        Err(e) => {
            tracing::warn!("Download failed: {}", e);
            Err(e)
        }
    }
}

fn open_db(path: Option<&PathBuf>) -> Option<sled::Db> {
    if let Some(sd_path) = &path {
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
    }
}

fn get_hit_rate(hit: usize, miss: usize) -> f64 {
    if hit + miss == 0 {
        tracing::warn!("hit + miss == 0. Please double-check your configuration.");
        return 0.0;
    }
    hit as f64 / (hit + miss) as f64 * 100.0
}

pub static BAR_MANAGER: OnceLock<kyuri::Manager> = OnceLock::new();

#[tokio::main]
async fn main() {
    let enable_color = std::env::var("NO_COLOR").is_err();
    BAR_MANAGER.get_or_init(|| {
        let manager = kyuri::Manager::new(std::time::Duration::from_secs(1));
        manager.set_ticker(true);
        manager
    });
    let bar_writer = BAR_MANAGER.get().unwrap().create_writer();
    tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(
            // https://github.com/tokio-rs/tracing/issues/735
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_ansi(enable_color)
        .with_writer(Mutex::new(bar_writer))
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

    let remote_sizedb = open_db(args.remote_sizedb.as_ref());
    let local_sizedb = open_db(args.local_sizedb.as_ref());

    // change cwd
    std::env::set_current_dir(&args.repo_path).expect("change cwd failed");

    let vote = stage1(&args);
    let stats = stage2(&args, local_sizedb.as_ref());
    let normalized_vote = stage3(&args, &vote, &stats, &client, remote_sizedb.as_ref()).await;
    let result = stage4(
        &args,
        &normalized_vote,
        &stats,
        &client,
        local_sizedb.as_ref(),
        remote_sizedb.as_ref(),
    )
    .await;
    match result {
        Ok(_) => {
            tracing::info!("All done!");
        }
        Err(e) => {
            tracing::error!("Error: {}", e);
            match e {
                Stage4Error::DownloadErrorOverThreshold => {
                    std::process::exit(1);
                }
                Stage4Error::LocalRemoveError(_) => {
                    std::process::exit(2);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_uri_normalize() {
        assert_eq!(
            log_uri_normalize("/test/a/../test?aaa=bbb&ccc=ddd#aaaaa").unwrap(),
            "/test/test"
        );
        assert_eq!(log_uri_normalize("/test////abc").unwrap(), "/test/abc");
        assert_eq!(log_uri_normalize("http://mirrors.ustc.edu.cn/nix-channels/store/kvnv3yfhwdvmmci261m092llmrwkw2rr.narinfo").unwrap(), "/nix-channels/store/kvnv3yfhwdvmmci261m092llmrwkw2rr.narinfo");
        assert_eq!(
            log_uri_normalize(
                "/anaconda/cloud/conda-forge/linux-64/x264-1%21164.3095-h166bdaf_2.tar.bz2"
            )
            .unwrap(),
            "/anaconda/cloud/conda-forge/linux-64/x264-1!164.3095-h166bdaf_2.tar.bz2"
        );
        assert_eq!(
            log_uri_normalize("/memtest86+/test.txt").unwrap(),
            "/memtest86+/test.txt"
        );
    }
}
