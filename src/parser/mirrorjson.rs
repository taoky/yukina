use std::net::IpAddr;

use serde::Deserialize;

use super::{LogItem, LogParser};

#[derive(Deserialize)]
struct RawLogItem {
    timestamp: f64,     // $msec
    clientip: String,   // $remote_addr
    url: String,        // $request_uri
    size: u64,          // $body_bytes_sent
    status: u16,        // $status
    user_agent: String, // $http_user_agent
}

#[derive(Default)]
pub struct MirrorJsonParser {}

impl LogParser for MirrorJsonParser {
    fn parse(&self, line: &str) -> anyhow::Result<super::LogItem> {
        let raw: RawLogItem = serde_json::from_str(line)?;
        let client: IpAddr = raw.clientip.parse()?;
        let secs = raw.timestamp.trunc() as i64;
        let mut nsecs = ((raw.timestamp - secs as f64) * 1_000_000_000.0) as u32;
        let secs = if nsecs == 1_000_000_000 {
            nsecs = 0;
            secs + 1
        } else {
            secs
        };
        let datetime = chrono::DateTime::from_timestamp(secs, nsecs)
            .ok_or_else(|| anyhow::anyhow!("invalid timestamp"))?;

        Ok(LogItem {
            client,
            time: datetime.into(),
            url: raw.url,
            size: raw.size,
            status: raw.status,
            user_agent: raw.user_agent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mirrorjson_parse() {
        let parser = MirrorJsonParser::default();
        let log = r#"{"timestamp":1761247176.709,"clientip":"114:514:19:19::810","serverip":"aaa:bbb:cccc:dd::eee","method":"GET","scheme":"https","url":"/debian-security/dists/bookworm-security/main/i18n/by-hash/SHA256/f23868ba5088b8f7e16f25c0d05192f8a4d28754d3b9e21f58d181f1aa3b8484","status":200,"size":170920,"resp_time":0.024,"http_host":"www.example.com","referer":"","user_agent":"?","request_id":"redacted","proto":"HTTP/1.1","proxied":"0"}
"#;
        let item = parser.parse(log).unwrap();
        assert_eq!(item.client, "114:514:19:19::810".parse::<IpAddr>().unwrap());
        assert_eq!(item.url, "/debian-security/dists/bookworm-security/main/i18n/by-hash/SHA256/f23868ba5088b8f7e16f25c0d05192f8a4d28754d3b9e21f58d181f1aa3b8484");
        assert_eq!(item.size, 170920);
        assert_eq!(item.status, 200);
        assert_eq!(item.user_agent, "?");
        assert_eq!(item.time.to_rfc3339(), "2025-10-23T19:19:36.709000110+00:00");
    }
}
