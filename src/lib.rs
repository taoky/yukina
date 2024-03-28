// Shared part with the kv binary
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SizeDBItem {
    pub size: Option<u64>,
    pub record_time: DateTime<Utc>,
}
