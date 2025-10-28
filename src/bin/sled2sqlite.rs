// This file is initially vibe-coded by GPT-5.
// It provides a binary to migrate sled to SQLite.

use clap::Parser;
use std::path::PathBuf;

/// Migrate a sled key-value database into a SQLite file using the kv_sqlite schema.
///
/// Notes:
/// - kv_sqlite stores keys as TEXT. This tool requires sled keys to be valid UTF-8 by default.
/// - If your sled keys are not UTF-8, pass --hex-encode-invalid-keys to encode keys as hex strings.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the sled database directory
    #[arg(long)]
    sled: PathBuf,

    /// Path to the output SQLite file (created if missing)
    #[arg(long)]
    sqlite: PathBuf,

    /// Optional sled tree name. If omitted, migrates the default/root tree.
    #[arg(long)]
    tree: Option<String>,

    /// Commit in batches of this many rows (helps with very large datasets)
    #[arg(long, default_value_t = 50_000)]
    batch_size: usize,

    /// If a sled key is not valid UTF-8, convert it to UTF-8 string with possible data loss.
    #[arg(long, default_value_t = false)]
    lossy_utf8: bool,
}

fn main() {
    let args = Args::parse();
    yukina::contrib::sled2sqlite::sled2sqlite(
        &args.sled,
        &args.sqlite,
        args.tree,
        args.batch_size,
        args.lossy_utf8,
    )
    .unwrap();
}
