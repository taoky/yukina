use anyhow::Result;
use chrono::{DateTime, TimeDelta, Utc};
use core::fmt;
use std::{
    collections::{BinaryHeap, HashMap, HashSet},
    io::{BufRead, BufReader},
    time::SystemTime,
};
use yukina::{db_get, db_remove, db_set, LocalSizeDBItem, RemoteSizeDBItem};

use crate::{
    construct_url, deduce_log_file_type, download_file, get_hit_rate, get_ip_prefix_string,
    get_progress_bar, head_file, insert_remotedb, log_uri_normalize, matches_filter,
    normalize_vote,
    parser::{get_log_parser, LogItem},
    remove_file, Cli, FileStats, LogFileType, NormalizedFileStats, NormalizedVote,
    NormalizedVoteItem, UserVote, VoteValue,
};

#[derive(Debug, Eq, PartialEq, Hash)]
struct IpPrefixUrl {
    ip_prefix: String,
    url: String,
}

fn process_logitem(
    args: &Cli,
    item: LogItem,
    vote: &mut HashMap<String, VoteValue>,
    access_record: &mut HashMap<IpPrefixUrl, DateTime<Utc>>,
    now_utc: DateTime<Utc>,
    hit: &mut usize,
    miss: &mut usize,
) -> bool {
    // Returns true if should stop processing further logs
    let path = log_uri_normalize(&item.url);
    let path = match path {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Invalid path: {}, with err {}", item.url, e);
            return false;
        }
    };
    let duration = now_utc.signed_duration_since(item.time);
    if duration > TimeDelta::from_std(*args.log_duration).unwrap() {
        return true;
    }
    if !args.include_browser_ua && item.user_agent.starts_with("Mozilla") {
        return false;
    }
    let client_prefix = get_ip_prefix_string(item.client);
    let ip_prefix_url = IpPrefixUrl {
        ip_prefix: client_prefix,
        url: path.clone(),
    };
    if let Some(last_time) = access_record.get(&ip_prefix_url) {
        let delta = item.time.signed_duration_since(*last_time);
        if delta.num_seconds() < 60 * 5 {
            return false;
        }
    }
    // strip prefix of the path, convert /reponame/some/path/xxx => /some/path/xxx
    let mut path = match path.strip_prefix(&format!("/{}", args.name)) {
        Some(p) => p,
        None => {
            tracing::warn!(
                "unexpected strip prefix (repo name) failed for path {}",
                path
            );
            return false;
        }
    };
    // strip further to match repopath
    if let Some(prefix) = &args.strip_prefix {
        path = match path.strip_prefix(prefix) {
            Some(p) => p,
            None => {
                tracing::debug!(
                    "unexpected strip prefix (user-given) failed for path {}",
                    path
                );
                return false;
            }
        };
    }
    // path shall not start with `/`
    if path.starts_with('/') {
        path = path.strip_prefix('/').unwrap();
    }
    if path.is_empty() {
        return false;
    }
    // path now looks like path/xxx
    if !matches_filter(path, &args.filter) {
        return false;
    }
    let vote = vote.entry(path.to_owned()).or_default();
    vote.count += 1;
    if (item.status == 200 || item.status == 206) && !item.proxied {
        vote.success_count += 1;
        *hit += 1;
    } else if item.status == 302 || item.status == 404 || item.proxied {
        vote.reject_count += 1;
        *miss += 1;
    } else {
        tracing::debug!("Unknown status: {}", item.status);
        vote.unknown_count += 1;
    }
    vote.resp_size = vote.resp_size.max(item.size);
    access_record.insert(ip_prefix_url, item.time.into());

    false
}

/// Analyse nginx logs and get user votes
pub fn stage1(args: &Cli) -> UserVote {
    let mut entries: Vec<_> = std::fs::read_dir(&args.log_path)
        .expect("read log path failed")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_type().ok().is_some_and(|ft| ft.is_file())
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|s| s.starts_with(&format!("{}.log", args.name)))
        })
        .collect();
    entries.sort_by_cached_key(|entry| {
        std::cmp::Reverse(
            entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH),
        )
    });

    tracing::debug!("Entries: {:?}", entries);

    let now_utc = chrono::Utc::now();
    let combined_parser = get_log_parser(args.log_format);

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
        tracing::info!("Processing {}", filename);
        // decide whether directly read the file, or use a decompressor
        let filetype = deduce_log_file_type(filename);

        let mut child_process = None;
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
                child_process = Some(output);
                let stdout = child_process
                    .as_mut()
                    .unwrap()
                    .stdout
                    .take()
                    .expect("get stdout failed");
                std::io::BufReader::new(Box::new(stdout))
            }
        };

        for line in bufreader.lines() {
            let line = line.expect("read line failed");
            let item = combined_parser.parse(&line).expect("parse line failed");
            stop_iterate_flag = process_logitem(
                args,
                item,
                &mut vote,
                &mut access_record,
                now_utc,
                &mut hit,
                &mut miss,
            );
            if stop_iterate_flag {
                break;
            }
        }

        // Reap child processes, if any
        if let Some(mut child) = child_process {
            let _ = child.wait();
        }
    }

    // Get sorted vote "report".
    let mut vote: Vec<_> = vote.into_iter().collect();
    vote.sort_by_key(|(_, size)| std::cmp::Reverse(*size));

    let total_size = vote.iter().map(|(_, v)| v.resp_size).sum::<u64>();
    tracing::info!(
        "Got {} votes, total (existing) size {}",
        vote.len(),
        humansize::format_size(total_size, humansize::BINARY)
    );
    tracing::info!(
        "(From nginx log) Hit: {}, Miss: {}, Estimated Hit rate: {:.2}%",
        hit,
        miss,
        get_hit_rate(hit, miss)
    );

    vote
}

/// Analyse local files and get metadata of files we are interested in
pub fn stage2(args: &Cli, local_sizedb: Option<&crate::db::Db>) -> FileStats {
    fn get_path_from_walkdir_entry(
        repo_path: &std::path::Path,
        entry: Result<&walkdir::DirEntry, &walkdir::Error>,
    ) -> String {
        let path = match entry {
            Ok(e) => e.path().to_owned(),
            Err(e) => {
                tracing::warn!("walkdir entry error: {}", e);
                e.path().expect("empty path in walkdir error").to_owned()
            }
        };
        path.strip_prefix(repo_path)
            .expect("unexpected strip prefix failed")
            .to_str()
            .expect("unexpected path conversion failed")
            .to_string()
    }

    let mut res = Vec::new();
    for entry in walkdir::WalkDir::new(&args.repo_path) {
        // do some filtering first -- in case dir is not accessible, etc.
        let path = get_path_from_walkdir_entry(&args.repo_path, entry.as_ref());
        let path = path.as_str();
        // path shall not start with `/`.
        assert!(!path.starts_with('/'));
        if !matches_filter(path, &args.filter) {
            continue;
        }

        let entry = entry.expect("walkdir failed");
        // We're not interested in symlinks, etc., and dirs means that we're not in the leaf node
        if !entry.file_type().is_file() {
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
    res.sort_by_key(|(_, size)| std::cmp::Reverse(*size));

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
    remote_sizedb: Option<&crate::db::Db>,
) -> NormalizedVote {
    let mut res = Vec::new();
    let progressbar = get_progress_bar(vote.len() as u64, "Stage 3", None);
    // Stats counters
    #[derive(Debug, Default)]
    struct HitMissStats {
        /// File exists locally
        local_hit: usize,
        /// File does not exist locally, but exists in sizedb
        sizedb_hit: usize,
        /// File does not exist locally, and sizedb shows that it does not exist remotely
        sizedb_nonexist: usize,
        /// File does not exist locally and in sizedb, but exists remotely
        remote_hit: usize,
        /// File does not exist locally and in sizedb, and does not exist remotely
        remote_miss: usize,
        /// For files exist locally or remotely, the sum of success_count
        local_hit_with_vote: usize,
        /// For files exist locally or remotely, the sum of reject_count
        real_miss_with_vote: usize,
    }

    impl HitMissStats {
        fn update_with_vote(&mut self, vote_value: &VoteValue) {
            self.local_hit_with_vote += vote_value.success_count as usize;
            self.real_miss_with_vote += vote_value.reject_count as usize;
        }
    }
    let mut hit_stats = HitMissStats::default();

    for vote_item in vote {
        progressbar.inc(1);
        let (url_path, vote_value) = vote_item;
        // Check if it exists
        let (size, exists, valid) = if let Some(value) = stats.hm.get(url_path) {
            tracing::debug!("File exists: {} ({})", url_path, value);
            hit_stats.local_hit += 1;
            hit_stats.update_with_vote(vote_value);
            (*value, true, true)
        } else {
            // if vote count less than min_vote_count, count in stats and skip
            if vote_value.count < args.min_vote_count {
                // don't really try to get size, to simplify logic and save some network requests
                hit_stats.update_with_vote(vote_value);
                continue;
            }
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
                        hit_stats.sizedb_hit += 1;
                        hit_stats.update_with_vote(vote_value);
                        (size, false, true)
                    }
                    None => {
                        tracing::info!("File not found at remote (from sizedb): {}", url_path);
                        hit_stats.sizedb_nonexist += 1;
                        (0, false, false)
                    }
                }
            } else {
                if args.gc_only {
                    // Don't do remote requests even if file does not exist, when gc_only is on.
                    continue;
                }
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
                        hit_stats.remote_hit += 1;
                        hit_stats.update_with_vote(vote_value);
                        insert_remotedb(remote_sizedb, url_path, Some(size));
                        (size, false, true)
                    }
                    Err(e) => {
                        tracing::info!("Invalid file ({}): {}", e, url_path);
                        let is_404 = e.status().is_some_and(|s| s == 404);
                        if is_404 {
                            insert_remotedb(remote_sizedb, url_path, None);
                        }
                        hit_stats.remote_miss += 1;
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
            res.push(NormalizedVoteItem {
                path: url_path.clone(),
                stats: NormalizedFileStats {
                    score: normalize_vote(vote_value.count, size),
                    original_score: vote_value.count,
                    size,
                    exists_local: exists,
                },
            });
        }
    }
    tracing::info!(
        "Local hit: {}, SizeDB hit: {}, SizeDB 404: {}, Remote hit: {}, Remote miss: {}",
        hit_stats.local_hit,
        hit_stats.sizedb_hit,
        hit_stats.sizedb_nonexist,
        hit_stats.remote_hit,
        hit_stats.remote_miss
    );
    tracing::info!(
        "Local hit with vote: {}, Real miss with vote: {}, Hit rate: {:.2}%",
        hit_stats.local_hit_with_vote,
        hit_stats.real_miss_with_vote,
        get_hit_rate(hit_stats.local_hit_with_vote, hit_stats.real_miss_with_vote)
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
    local_sizedb: Option<&crate::db::Db>,
    remote_sizedb: Option<&crate::db::Db>,
) -> Result<(), Stage4Error> {
    let extension = args.extension.as_ref().map(|x| x.build(args));
    let mut sum = stats.list.iter().map(|(_, size)| *size).sum::<u64>();
    let max = args.size_limit;

    // Two "queues"
    // Max heap: take largest first
    let mut to_download_queue: BinaryHeap<_> = normalized_vote
        .iter()
        .filter(|x| !x.stats.exists_local)
        .cloned()
        .collect();
    // Min heap: take smallest first
    let mut to_remove_queue: BinaryHeap<_> = normalized_vote
        .iter()
        .filter(|x| x.stats.exists_local)
        .cloned()
        .map(std::cmp::Reverse)
        .collect();
    // for files get no votes, add to to_remove_queue with 0 score
    {
        let to_remove_hs: HashSet<_> = to_remove_queue.iter().map(|x| x.0.path.clone()).collect();
        for item in stats.list.clone() {
            if !to_remove_hs.contains(&item.0) {
                to_remove_queue.push(std::cmp::Reverse(NormalizedVoteItem {
                    path: item.0,
                    stats: NormalizedFileStats {
                        score: 0.0,
                        original_score: 0,
                        size: item.1,
                        exists_local: true,
                    },
                }));
            }
        }
    }

    if args.aggressive_removal {
        loop {
            let local_item = match to_remove_queue.peek() {
                None => break,
                Some(item) => item,
            };
            // check if score is 0.0
            if local_item.0.stats.score != 0.0 {
                break;
            }
            // pop it out first
            let local_item = to_remove_queue
                .pop()
                .expect("unexpected pop failure when peek succeeds")
                .0;
            if let Err(e) = remove_file(args, &local_item, local_sizedb) {
                tracing::error!("Stopping due to error: {}", e);
                return Err(Stage4Error::LocalRemoveError(e));
            }
            sum -= local_item.stats.size;
        }
    }

    while sum > max {
        // well, it's too large even don't get anything
        // just remove!
        let local_item = to_remove_queue
            .pop()
            .expect("Nothing to remove while size exceeds")
            .0;
        if let Err(e) = remove_file(args, &local_item, local_sizedb) {
            // We tend to stop immediately if deletion error occurs, as it means that the total size of the repo could not be reduced.
            tracing::error!("Stopping due to error: {}", e);
            return Err(Stage4Error::LocalRemoveError(e));
        }
        sum -= local_item.stats.size;
    }

    if args.gc_only {
        // OK, we don't need to download anything in this case.
        return Ok(());
    }

    // Here, a download error counter is maintained: network is more likely to be unstable, so we're not going to stop the process immediately.
    // However, if the error count exceeds a certain threshold, we will stop the process.
    let mut download_error_cnt: usize = 0;

    fn increase_error_threshold(
        args: &Cli,
        download_error_cnt: &mut usize,
    ) -> Result<(), Stage4Error> {
        *download_error_cnt += 1;
        if args.download_error_threshold > 0 && *download_error_cnt > args.download_error_threshold
        {
            return Err(Stage4Error::DownloadErrorOverThreshold);
        }
        Ok(())
    }

    fn is_not_found(err: anyhow::Error) -> bool {
        if let Some(reqwest_err) = err.downcast_ref::<reqwest::Error>() {
            if reqwest_err.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                return true;
            }
        }
        false
    }

    // Extension might bring duplicated items...
    // Use a HashSet to store paths we've seen (downloaded)
    let mut seen = HashSet::new();
    async fn download_impl(
        args: &Cli,
        client: &reqwest::Client,
        local_sizedb: Option<&crate::db::Db>,
        remote_sizedb: Option<&crate::db::Db>,
        remote_item: NormalizedVoteItem,
        remote_size: u64,
        seen: &mut HashSet<String>,
        sum: &mut u64,
        to_download_queue: &mut BinaryHeap<NormalizedVoteItem>,
        extension: &Option<Box<dyn crate::extension::Extension>>,
        download_error_cnt: &mut usize,
    ) -> Result<(), Stage4Error> {
        if seen.insert(remote_item.path.clone()) {
            let download_state = download_file(args, &remote_item, client, extension).await;
            match download_state {
                Ok(actual_size) => {
                    if args.dry_run {
                        *sum += remote_size;
                    } else {
                        *sum += actual_size as u64;
                        if remote_size != actual_size as u64 {
                            tracing::warn!(
                                "Size mismatch: {} (remote) vs {} (actual)",
                                remote_size,
                                actual_size
                            );
                        }
                        let _ = db_set::<LocalSizeDBItem>(
                            local_sizedb,
                            &remote_item.path,
                            actual_size.into(),
                        );
                    }
                    // Run extension and push to download queue
                    if let Some(ext) = &extension {
                        if let Ok(res) = ext.parse_downloaded_file(args, &remote_item, client) {
                            if let Some(new_item) = res {
                                let new_item = new_item.clone();
                                tracing::info!("Extension {} result: {:?}", ext.name(), new_item);
                                to_download_queue.push(new_item);
                            }
                        } else {
                            tracing::warn!("Extension {} error: {:?}", ext.name(), remote_item);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Download error: {}", e);
                    if is_not_found(e) {
                        // Don't add to error count
                        // Skip and clear remote hit in db
                        tracing::info!(
                            "Remove {} from remote sizedb as it does not exist.",
                            remote_item.path
                        );
                        let _ = db_remove(remote_sizedb, &remote_item.path);
                    } else {
                        increase_error_threshold(args, download_error_cnt)?;
                    }
                }
            }
        }
        Ok(())
    }

    macro_rules! download {
        ($item: expr, $remote_size: expr) => {
            download_impl(
                args,
                client,
                local_sizedb,
                remote_sizedb,
                $item,
                $remote_size,
                &mut seen,
                &mut sum,
                &mut to_download_queue,
                &extension,
                &mut download_error_cnt,
            )
            .await?;
        };
    }

    while let Some(item) = to_download_queue.pop() {
        // does size fit?
        let remote_score = item.stats.score;
        let remote_size = item.stats.size;
        if sum.checked_add(remote_size).unwrap() <= max {
            download!(item, remote_size);
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
                }
                .0;
                // Compare score, if the file to download is even less popular than local one, stop.
                let local_size = local_item.stats.size;
                let local_score = local_item.stats.score;
                if local_score >= remote_score {
                    tracing::info!("Stopped downloading/removing.");
                    stop_flag = true;
                    break;
                }
                if let Err(e) = remove_file(args, &local_item, local_sizedb) {
                    tracing::error!("Stopping due to error: {}", e);
                    return Err(Stage4Error::LocalRemoveError(e));
                }
                sum -= local_size;
            }
            if stop_flag {
                break;
            }
            download!(item, remote_size);
        } else {
            unreachable!("sum > max");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binaryheap_order_correct() {
        let v1 = NormalizedVoteItem {
            path: "a".to_string(),
            stats: NormalizedFileStats {
                score: 1.0,
                original_score: 1,
                size: 1,
                exists_local: false,
            },
        };
        let v2 = NormalizedVoteItem {
            path: "b".to_string(),
            stats: NormalizedFileStats {
                score: 2.0,
                original_score: 2,
                size: 2,
                exists_local: false,
            },
        };
        let v3 = NormalizedVoteItem {
            path: "c".to_string(),
            stats: NormalizedFileStats {
                score: 2.0,
                original_score: 2,
                size: 3,
                exists_local: false,
            },
        };
        let mut b1 = BinaryHeap::new();
        b1.push(v1.clone());
        b1.push(v2.clone());
        b1.push(v3.clone());
        assert_eq!(b1.pop().unwrap().path, "b");
        assert_eq!(b1.pop().unwrap().path, "c");
        assert_eq!(b1.pop().unwrap().path, "a");
        let mut b2 = BinaryHeap::new();
        b2.push(std::cmp::Reverse(v1));
        b2.push(std::cmp::Reverse(v2));
        b2.push(std::cmp::Reverse(v3));
        assert_eq!(b2.pop().unwrap().0.path, "a");
        assert_eq!(b2.pop().unwrap().0.path, "c");
        assert_eq!(b2.pop().unwrap().0.path, "b");
    }
}
