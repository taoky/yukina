// Shared part with the kv binary
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RemoteSizeDBItem {
    pub size: Option<u64>,
    pub record_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LocalSizeDBItem {
    pub size: u64,
}

impl From<u64> for LocalSizeDBItem {
    fn from(size: u64) -> Self {
        LocalSizeDBItem { size }
    }
}

impl From<usize> for LocalSizeDBItem {
    fn from(size: usize) -> Self {
        LocalSizeDBItem { size: size as u64 }
    }
}

pub fn db_get<T>(db: Option<&sled::Db>, key: &str) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    if let Some(db) = db {
        let value = db.get(key)?;
        match value {
            Some(value) => Ok(bincode::deserialize(&value)?),
            None => Err(anyhow::anyhow!("Key not found")),
        }
    } else {
        Ok(T::default())
    }
}

pub fn db_set<T>(db: Option<&sled::Db>, key: &str, value: T) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    if let Some(db) = db {
        let value = bincode::serialize(&value)?;
        db.insert(key, value)?;
    }
    Ok(())
}

pub fn db_remove(db: Option<&sled::Db>, key: &str) -> anyhow::Result<()> {
    if let Some(db) = db {
        db.remove(key)?;
    }
    Ok(())
}
