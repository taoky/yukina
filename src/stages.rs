use anyhow::Result;
use chrono::{DateTime, Utc};
use core::fmt;
use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader},
    time::SystemTime,
};
use yukina::{db_get, db_set, LocalSizeDBItem, RemoteSizeDBItem};

use crate::{
    combined, construct_url, deduce_log_file_type, download_file, get_ip_prefix_string, head_file,
    insert_remotedb, matches_filter, normalize_vote, progressbar, relative_uri_normalize,
    remove_file, Cli, FileStats, LogFileType, NormalizedFileStats, NormalizedVote, UserVote,
    VoteValue,
};

/// Analyse nginx logs and get user votes
pub fn stage1(args: &Cli) -> UserVote {
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
pub fn stage2(args: &Cli, local_sizedb: Option<&sled::Db>) -> FileStats {
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
        let filesize = {
            let mut res = None;
            if let Ok(size) = db_get::<LocalSizeDBItem>(local_sizedb, path) {
                res = Some(size.size);
            } else {
                res = Some(
                    res.unwrap_or_else(|| entry.metadata().expect("get metadata failed").len()),
                );
                let _ = db_set::<LocalSizeDBItem>(local_sizedb, path, res.unwrap().into());
            }
            res.unwrap()
        };
        res.push((path.to_string(), filesize));
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

/// Get size of non-existing files, and normalize vote value
pub async fn stage3(
    args: &Cli,
    vote: &UserVote,
    stats: &FileStats,
    client: &reqwest::Client,
    remote_sizedb: Option<&sled::Db>,
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
            let mut size_item: Option<RemoteSizeDBItem> = None;
            let mut exceeded_miss_ttl = false;
            if let Ok(s) = db_get::<RemoteSizeDBItem>(remote_sizedb, url_path) {
                if s.size.is_none() {
                    let ttl: std::time::Duration = args.size_database_ttl.into();
                    let duration = Utc::now()
                        .signed_duration_since(s.record_time)
                        .to_std()
                        .unwrap_or_default();
                    if duration > ttl {
                        exceeded_miss_ttl = true;
                        let _ = remote_sizedb.unwrap().remove(url_path);
                    }
                }
                size_item = Some(s);
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
                let url = construct_url(args, url_path);
                tracing::debug!("Heading {:?}", url);
                let res = head_file(args, url.as_str(), client)
                    .await
                    .expect("head failed");
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
                        insert_remotedb(remote_sizedb, url_path, Some(size));
                        (size, false, true)
                    }
                    Err(e) => {
                        tracing::info!("Invalid file ({}): {}", e, url_path);
                        let is_404 = e.status().map_or(false, |s| s == 404);
                        if is_404 {
                            insert_remotedb(remote_sizedb, url_path, None);
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

#[derive(Debug)]
pub enum Stage4Error {
    LocalRemoveError(std::io::Error),
    DownloadErrorOverThreshold,
}

impl std::fmt::Display for Stage4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalRemoveError(e) => write!(f, "Local remove error: {}", e),
            Self::DownloadErrorOverThreshold => write!(f, "Download error over threshold"),
        }
    }
}

impl std::error::Error for Stage4Error {}

/// Generate report and download/remove (if not dry run)
pub async fn stage4(
    args: &Cli,
    normalized_vote: &NormalizedVote,
    stats: &FileStats,
    client: &reqwest::Client,
    local_sizedb: Option<&sled::Db>,
) -> Result<(), Stage4Error> {
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
        if let Err(e) = remove_file(args, &local_item.0, local_sizedb) {
            // We tend to stop immediately if deletion error occurs, as it means that the total size of the repo could not be reduced.
            tracing::error!("Stopping due to error: {}", e);
            return Err(Stage4Error::LocalRemoveError(e));
        }
        sum -= local_item.1.size;
    }

    // Here, a download error counter is maintained: network is more likely to be unstable, so we're not going to stop the process immediately.
    // However, if the error count exceeds a certain threshold, we will stop the process.
    let mut download_error_cnt: usize = 0;
    macro_rules! increase_error_threshold {
        ($c: expr) => {
            $c += 1;
            if $c > crate::DOWNLOAD_ERROR_THRESHOLD {
                return Err(Stage4Error::DownloadErrorOverThreshold.into());
            }
        };
    }

    macro_rules! download {
        ($remote_path: expr, $remote_size: expr) => {
            let download_state = download_file(args, &$remote_path, client).await;
            match download_state {
                Ok(actual_size) => {
                    if args.dry_run {
                        sum += $remote_size;
                    } else {
                        sum += actual_size as u64;
                        if ($remote_size as u64) != actual_size as u64 {
                            tracing::warn!(
                                "Size mismatch: {} (remote) vs {} (actual)",
                                $remote_size,
                                actual_size
                            );
                        }
                        let _ = db_set::<LocalSizeDBItem>(
                            local_sizedb,
                            &$remote_path,
                            actual_size.into(),
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Download error: {}", e);
                    increase_error_threshold!(download_error_cnt);
                }
            }
        };
    }

    while let Some(item) = to_download_queue.pop() {
        // does size fit?
        let remote_score = item.1.score;
        let remote_size = item.1.size;
        let remote_path = item.0.clone();
        if sum.checked_add(remote_size).unwrap() <= max {
            download!(remote_path, remote_size);
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
                if let Err(e) = remove_file(args, &local_item.0, local_sizedb) {
                    tracing::error!("Stopping due to error: {}", e);
                    return Err(Stage4Error::LocalRemoveError(e));
                }
                sum -= local_size;
            }
            if stop_flag {
                break;
            }
            download!(remote_path, remote_size);
        } else {
            unreachable!("sum > max");
        }
    }
    Ok(())
}
