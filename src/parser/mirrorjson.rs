use std::{borrow::Cow, net::IpAddr};

use serde::Deserialize;

use super::{LogItem, LogParser};

#[derive(Deserialize)]
struct RawLogItem<'a> {
    timestamp: f64, // $msec
    #[serde(borrow)]
    clientip: Cow<'a, str>, // $remote_addr
    #[serde(borrow)]
    url: Cow<'a, str>, // $request_uri
    size: u64,      // $body_bytes_sent
    status: u16,    // $status
    #[serde(borrow)]
    user_agent: Cow<'a, str>, // $http_user_agent
    #[serde(default, borrow)]
    proxied: Cow<'a, str>, // custom field to indicate if the request was proxied
}

#[derive(Default)]
pub struct MirrorJsonParser {}

impl LogParser for MirrorJsonParser {
    fn parse<'a>(&self, line: &'a str) -> anyhow::Result<LogItem<'a>> {
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
            proxied: raw.proxied != "0",
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
        assert_eq!(
            item.time.to_rfc3339(),
            "2025-10-23T19:19:36.709000110+00:00"
        );
        assert_eq!(item.proxied, false);
    }

    #[test]
    fn json_borrows_plain_strings_and_decodes_escaped_strings() {
        let parser = MirrorJsonParser::default();
        let plain = r#"{"timestamp":1761247176,"clientip":"192.0.2.1","url":"/test/file","size":42,"status":200,"user_agent":"client","proxied":"0"}"#;
        let item = parser.parse(plain).unwrap();
        assert!(matches!(item.url, Cow::Borrowed(_)));
        assert!(matches!(item.user_agent, Cow::Borrowed(_)));
        assert!(!item.proxied);

        let escaped = r#"{"timestamp":1761247176,"clientip":"192.0.2.\u0031","url":"\/test\/\u6587\u4ef6","size":42,"status":200,"user_agent":"a\"b\\c","proxied":"\u0030"}"#;
        let item = parser.parse(escaped).unwrap();
        assert_eq!(item.client, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(item.url, "/test/文件");
        assert_eq!(item.user_agent, "a\"b\\c");
        assert!(!item.proxied);
        assert!(matches!(item.url, Cow::Owned(_)));
        assert!(matches!(item.user_agent, Cow::Owned(_)));

        // Preserve the existing interpretation of a missing proxied field.
        let missing = plain.replace(",\"proxied\":\"0\"", "");
        assert!(parser.parse(&missing).unwrap().proxied);
    }
}
