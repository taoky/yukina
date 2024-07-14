// parse combined log format
// Ref:
// - https://github.com/taoky/ayano/blob/master/parser/nginx-combined.go
// - https://github.com/taoky/ayano/blob/master/parser/clf-timeparse.go

use anyhow::{anyhow, Result};
use chrono::{DateTime, FixedOffset, NaiveDate};
use std::{collections::HashMap, net::IpAddr};

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

pub struct CombinedParser {
    clf_month_map: HashMap<String, u32>,
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

impl Default for CombinedParser {
    fn default() -> Self {
        CombinedParser {
            clf_month_map: clf_month_map(),
        }
    }
}

impl CombinedParser {
    fn clf_date_parse(&self, s: &str) -> Result<DateTime<FixedOffset>> {
        let month_map = &self.clf_month_map;

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

    pub fn parse(&self, line: &str) -> Result<LogItem> {
        let mut parts = line.splitn(2, " - ");
        let client = parts
            .next()
            .ok_or(anyhow!("No client IP found"))?
            .to_string();
        // tracing::debug!("client: {:?}", client);

        let rest = parts
            .next()
            .ok_or(anyhow!("Unexpected log format after client IP"))?;

        // Extracting the time
        let time_start = rest
            .find('[')
            .ok_or(anyhow!("No opening bracket for time found"))?
            + 1;
        let time_end = rest
            .find(']')
            .ok_or(anyhow!("No closing bracket for time found"))?;
        let time_str = &rest[time_start..time_end];
        // tracing::debug!("time_str: {:?}", time_str);
        let time = self.clf_date_parse(time_str)?;

        // Extract the URL from the request
        let request_start = rest
            .find('"')
            .ok_or(anyhow!("No opening quote for request found"))?
            + 1;
        let request_end = rest[request_start..]
            .find('"')
            .ok_or(anyhow!("No closing quote for request found"))?
            + request_start;
        let request_str = &rest[request_start..request_end];
        let url = request_str
            .split_whitespace()
            .nth(1)
            .ok_or(anyhow!("No URL found in request"))?
            .to_string();
        // tracing::debug!("url: {:?}", url);

        // tracing::debug!("rest: {:?}", &rest[request_end + 2..]);
        // Extracting the size after the second '"'
        let rest = &rest[request_end + 2..];
        let status_end = rest.find(' ').ok_or(anyhow!("No space after URL found"))?;
        let status_str = &rest[..status_end];
        let status: u16 = status_str.parse()?;
        // tracing::debug!("status: {:?}", status);

        let size_start = status_end + 1;
        let size_end = rest[size_start..]
            .find(' ')
            .ok_or(anyhow!("No space after status found"))?
            + size_start;
        let size_str = &rest[size_start..size_end];
        let size: u64 = size_str.parse()?;
        // tracing::debug!("size: {:?}", size);

        // find third " as user agent start
        let rest = &rest[size_end + 1..];
        let matches = rest.match_indices('"').collect::<Vec<_>>();
        let user_agent_start = matches[2].0 + 1;
        let user_agent_end = matches[3].0;
        let user_agent = &rest[user_agent_start..user_agent_end];
        // tracing::debug!("user_agent: {:?}", user_agent);

        Ok(LogItem {
            client: client.parse()?,
            time,
            url,
            size,
            status,
            user_agent: user_agent.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use test_log::test;

    #[test]
    fn test_clf_date_parse() {
        let parser = CombinedParser::default();
        let datetime = parser.clf_date_parse("01/Jan/2021:00:00:00 +0000").unwrap();
        assert_eq!(datetime.to_rfc3339(), "2021-01-01T00:00:00+00:00");
    }

    #[test]
    fn test_combined_parse() {
        let parser = CombinedParser::default();
        let log = r#"123.45.67.8 - - [12/Mar/2023:00:15:32 +0800] "GET /path/to/a/file HTTP/1.1" 200 3009 "-" """#;
        let item = parser.parse(log).unwrap();
        assert_eq!(item.client, IpAddr::from_str("123.45.67.8").unwrap());
        assert_eq!(item.url, "/path/to/a/file");
        assert_eq!(item.size, 3009);
        assert_eq!(item.status, 200);
        assert_eq!(item.time.to_rfc3339(), "2023-03-12T00:15:32+08:00");
        assert_eq!(item.user_agent, "");
    }
}
