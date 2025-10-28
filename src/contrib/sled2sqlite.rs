// This file is initially vibe-coded by GPT-5.
// It provides a function to migrate sled to SQLite.

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use std::{
    path::Path,
    time::{Duration, Instant},
};

pub fn sled2sqlite(
    sled_path: &Path,
    sqlite_path: &Path,
    tree: Option<String>,
    batch_size: usize,
    lossy_utf8: bool,
) -> Result<()> {
    // Open sled database
    let sled_db = sled::open(sled_path)
        .with_context(|| format!("opening sled db at {}", sled_path.display()))?;

    // Build iterator over the chosen tree
    let iter = if let Some(tree_name) = &tree {
        sled_db
            .open_tree(tree_name)
            .with_context(|| format!("opening sled tree {:?}", tree_name))?
            .iter()
    } else {
        sled_db.iter()
    };

    // Open SQLite and ensure schema exists
    let mut conn = Connection::open(sqlite_path)
        .with_context(|| format!("opening sqlite at {}", sqlite_path.display()))?;
    conn.busy_timeout(Duration::from_secs(30))?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS kv (
            k TEXT PRIMARY KEY,
            v BLOB NOT NULL
        );
        "#,
    )?;

    // Bulk insert within transactions
    let start = Instant::now();
    let mut total = 0usize;

    let mut tx = conn.transaction()?;
    let mut stmt = tx.prepare(
        "INSERT INTO kv (k, v) VALUES (?1, ?2)
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
    )?;

    for kv in iter {
        let (k, v) = kv?;
        let k_str = match std::str::from_utf8(&k) {
            Ok(s) => s.to_owned(),
            Err(_) if lossy_utf8 => String::from_utf8_lossy(&k).to_string(),
            Err(_) => {
                drop(stmt);
                tx.rollback()?;
                bail!("Encountered non-UTF-8 key. Offending key (hex): {:x?}", &k);
            }
        };

        stmt.execute(params![k_str, v.as_ref()])?;
        total += 1;

        if total.is_multiple_of(batch_size) {
            drop(stmt);
            tx.commit()?;
            tx = conn.transaction()?;
            stmt = tx.prepare(
                "INSERT INTO kv (k, v) VALUES (?1, ?2)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            )?;
        }
    }

    drop(stmt);
    tx.commit()?;

    println!(
        "Migrated {} entries in {:.2}s into {}",
        total,
        start.elapsed().as_secs_f64(),
        sqlite_path.display()
    );

    Ok(())
}
