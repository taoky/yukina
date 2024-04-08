#![warn(clippy::cognitive_complexity)]
use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use futures_util::{stream::StreamExt, Future};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use parse_size::parse_size;
use regex::Regex;
use std::{collections::HashMap, io::Write, net::IpAddr, path::PathBuf};
use tracing_subscriber::EnvFilter;
use url::Url;
use yukina::{db_remove, db_set, RemoteSizeDBItem};

use shadow_rs::shadow;
shadow!(build);

mod combined;
mod stages;
mod term;

use stages::*;

fn parse_bytes(s: &str) -> Result<u64, clap::Error> {
    parse_size(s).map_err(|e| clap::Error::raw(clap::error::ErrorKind::ValueValidation, e))
}

fn get_version() -> &'static str {
    if build::SHORT_COMMIT.is_empty() {
        build::LAST_TAG
    } else {
        build::SHORT_COMMIT
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

    /// Minimum vote count to consider a file in stage 1.
    #[clap(long, default_value_t = 2)]
    min_vote_count: u64,

    /// Retry count for each request.
    #[clap(long, default_value_t = 3)]
    retry: usize,
}

const DOWNLOAD_ERROR_THRESHOLD: usize = 5;

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
type NormalizedVoteItem = (String, NormalizedFileStats);
type NormalizedVote = Vec<NormalizedVoteItem>;

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
    let path = &item.0;
    let full_path = args.repo_path.join(path);
    if args.dry_run {
        tracing::info!("Would remove: {:?}", full_path);
        return Ok(());
    }
    if let Err(e) = std::fs::remove_file(&full_path) {
        tracing::warn!("Remove file failed: {:?}", e);
        return Err(e);
    }

    tracing::info!("Removed: {:?} (score = {})", full_path, item.1.score);
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
) -> Result<usize> {
    let path = &item.0;
    let url = construct_url(args, path);
    if args.dry_run {
        tracing::info!("Would download: {} -> {:?}", url, args.repo_path.join(path));
        return Ok(0);
    }
    tracing::info!("Downloading {} (score = {})", url, item.1.score);
    async fn download(
        args: &Cli,
        path: &str,
        url: &str,
        client: &reqwest::Client,
    ) -> Result<usize> {
        let resp = client.get(url).send().await?.error_for_status()?;
        let total_size = resp.content_length();
        let progressbar = progressbar!(total_size);
        progressbar.set_message(format!("Downloading: {}", url));

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
        std::fs::rename(&tmp_path, &target_path)?;
        progressbar.finish();
        Ok(std::fs::metadata(&target_path)?.len() as usize)
    }
    match again(|| download(args, path, url.as_str(), client), args.retry).await {
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
    assert!(hit + miss > 0);
    hit as f64 / (hit + miss) as f64 * 100.0
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
    fn test_relative_uri_normalize() {
        assert_eq!(
            relative_uri_normalize("/test/a/../test?aaa=bbb&ccc=ddd#aaaaa"),
            "/test/test"
        );
        assert_eq!(relative_uri_normalize("/test////abc"), "/test/abc")
    }
}
