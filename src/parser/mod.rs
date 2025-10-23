use std::{collections::HashMap, net::IpAddr};

use anyhow::{anyhow, Result};
use chrono::{DateTime, FixedOffset, NaiveDate};

pub mod combined;

#[derive(Debug)]
pub struct LogItem {
    pub client: IpAddr,
    pub time: DateTime<FixedOffset>,
    pub url: String,
    pub size: u64,
    pub status: u16,
    #[allow(dead_code)]
    pub user_agent: String,
}

pub trait LogParser {
    fn parse(&self, line: &str) -> Result<LogItem>;
}

fn clf_month_map() -> HashMap<String, u32> {
    let months = vec![
        ("Jan", 1),
        ("Feb", 2),
        ("Mar", 3),
        ("Apr", 4),
        ("May", 5),
        ("Jun", 6),
        ("Jul", 7),
        ("Aug", 8),
        ("Sep", 9),
        ("Oct", 10),
        ("Nov", 11),
        ("Dec", 12),
    ];

    months
        .into_iter()
        .map(|(m, v)| (m.to_string(), v))
        .collect()
}

fn clf_date_parse(s: &str) -> Result<DateTime<FixedOffset>> {
    let month_map = clf_month_map();

    let day: u32 = s[0..2].parse()?;
    let month_str = &s[3..6];
    let month = *month_map
        .get(month_str)
        .ok_or_else(|| anyhow!("invalid month"))?;
    let year: i32 = s[7..11].parse()?;
    let hour: u32 = s[12..14].parse()?;
    let minute: u32 = s[15..17].parse()?;
    let second: u32 = s[18..20].parse()?;

    let timezone_sign = if &s[21..22] == "-" { -1 } else { 1 };
    let timezone_hour: i32 = s[22..24].parse().unwrap();
    let timezone_offset = timezone_sign * timezone_hour * 3600;
    let timezone = FixedOffset::east_opt(timezone_offset).ok_or(anyhow!("invalid timezone"))?;

    let datetime = NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, second))
        .map(|date| date.and_local_timezone(timezone))
        .ok_or(anyhow!("invalid datetime"))?;
    let datetime = datetime
        .single()
        .ok_or(anyhow!("ambiguous or invalid datetime"))?;
    Ok(datetime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clf_date_parse() {
        let datetime = clf_date_parse("01/Jan/2021:00:00:00 +0000").unwrap();
        assert_eq!(datetime.to_rfc3339(), "2021-01-01T00:00:00+00:00");
    }
}
