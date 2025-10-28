// This file is initially vibe-coded by GPT-5.
// It is used to provide a similar interface to sled DB, but backed by SQLite, to replace sled.

use rusqlite::{params, Connection, OptionalExtension};

pub type Result<T> = std::result::Result<T, rusqlite::Error>;

pub struct Db {
    conn: Connection,
}

impl Db {
    // Open a file-backed DB (creates it if it doesn't exist)
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Db { conn };
        db.init()?;
        Ok(db)
    }

    // Open an in-memory DB
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Db { conn };
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> Result<()> {
        self.conn.busy_timeout(std::time::Duration::from_secs(5))?;
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY,
                v BLOB NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    // db.get(key) -> Option<Vec<u8>>
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row("SELECT v FROM kv WHERE k = ?1", [key], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .optional()
    }

    // db.insert(key, value) - upsert semantics
    pub fn insert(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO kv (k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![key, value],
        )?;
        Ok(())
    }

    // db.remove(key) -> bool (true if a row was deleted)
    pub fn remove(&self, key: &str) -> Result<bool> {
        let changed = self.conn.execute("DELETE FROM kv WHERE k = ?1", [key])?;
        Ok(changed > 0)
    }

    // db.scan_prefix(prefix) -> Iterator over (key, value) where key starts with prefix.
    // Keys are TEXT; values are BLOBs (Vec<u8>).
    pub fn scan_prefix<'a>(&'a self, prefix: &str) -> Result<ScanIter<'a>> {
        let pattern = like_prefix_pattern(prefix);
        Ok(ScanIter {
            conn: &self.conn,
            pattern,
            last_key: None,
            done: false,
        })
    }
}

// Escape SQLite LIKE wildcards in the prefix, then append '%'.
// Uses '!' as the escape character.
fn like_prefix_pattern(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + 1);
    for ch in prefix.chars() {
        match ch {
            '!' | '%' | '_' => {
                out.push('!');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out.push('%');
    out
}

// Iterator that fetches the next row on each next() call.
// It performs a small query per step to avoid borrow/lifetime issues
// with rusqlite's Statement/Rows types.
pub struct ScanIter<'conn> {
    conn: &'conn Connection,
    pattern: String,
    last_key: Option<String>,
    done: bool,
}

impl<'conn> Iterator for ScanIter<'conn> {
    type Item = Result<(String, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let sql = if self.last_key.is_some() {
            "SELECT k, v
               FROM kv
              WHERE k LIKE ?1 ESCAPE '!' AND k > ?2
              ORDER BY k
              LIMIT 1"
        } else {
            "SELECT k, v
               FROM kv
              WHERE k LIKE ?1 ESCAPE '!'
              ORDER BY k
              LIMIT 1"
        };

        let mut stmt = match self.conn.prepare(sql) {
            Ok(s) => s,
            Err(e) => return Some(Err(e)),
        };

        let res = if let Some(ref last) = self.last_key {
            stmt.query_row(params![&self.pattern, last], |row| {
                let k: String = row.get(0)?;
                let v: Vec<u8> = row.get(1)?;
                Ok((k, v))
            })
            .optional()
        } else {
            stmt.query_row(params![&self.pattern], |row| {
                let k: String = row.get(0)?;
                let v: Vec<u8> = row.get(1)?;
                Ok((k, v))
            })
            .optional()
        };

        match res {
            Err(e) => Some(Err(e)),
            Ok(None) => {
                self.done = true;
                None
            }
            Ok(Some((k, v))) => {
                self.last_key = Some(k.clone());
                Some(Ok((k, v)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops() -> Result<()> {
        let db = Db::open_in_memory()?;
        assert_eq!(db.get("a")?, None);

        db.insert("a", b"1")?;
        assert_eq!(db.get("a")?, Some(b"1".to_vec()));

        assert!(db.remove("a")?);
        assert_eq!(db.get("a")?, None);

        Ok(())
    }

    #[test]
    fn scan_prefix_works_and_escapes() -> Result<()> {
        let db = Db::open_in_memory()?;

        for (k, v) in [
            ("ab", b"1".as_slice()),
            ("aba!%", b"2".as_slice()),
            ("aba_%", b"3".as_slice()),
            ("abc", b"4".as_slice()),
            ("abd", b"5".as_slice()),
            ("b", b"6".as_slice()),
        ] {
            db.insert(k, v)?;
        }

        let items: Result<Vec<(String, Vec<u8>)>> = db.scan_prefix("ab")?.collect();
        let items = items?;

        let got_keys: Vec<String> = items.into_iter().map(|(k, _)| k).collect();
        assert_eq!(got_keys, vec!["ab", "aba!%", "aba_%", "abc", "abd"]);

        // Test escaping in the prefix itself
        let items2: Result<Vec<(String, Vec<u8>)>> = db.scan_prefix("aba!").unwrap().collect();
        let keys2: Vec<String> = items2?.into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys2, vec!["aba!%"]);

        Ok(())
    }
}
