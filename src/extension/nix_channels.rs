/// Parse narinfo file and get nar URL and size
use super::{get_target_file_path, Extension};
use crate::{normalize_vote, Cli, NormalizedFileStats, NormalizedVoteItem};
use anyhow::Result;

#[derive(Debug, Default)]
pub struct NixChannels;

fn narinfo_parse(contents: &str) -> Result<(String, u64)> {
    let mut url = String::new();
    let mut size = 0;
    for line in contents.lines() {
        if line.starts_with("URL: ") {
            url = line.trim_start_matches("URL: ").to_string();
            continue;
        } else if line.starts_with("FileSize: ") {
            size = line.trim_start_matches("FileSize: ").parse()?;
            continue;
        }
    }
    if url.is_empty() || size == 0 {
        return Err(anyhow::anyhow!("URL or FileSize not found"));
    }
    Ok((url, size))
}

impl Extension for NixChannels {
    fn name(&self) -> &'static str {
        "nixchannels"
    }

    fn parse(
        &self,
        args: &Cli,
        item: &NormalizedVoteItem,
        _client: &reqwest::Client,
    ) -> Result<Option<NormalizedVoteItem>> {
        if !item.path.ends_with(".narinfo") {
            return Ok(None);
        }
        let target_filepath = get_target_file_path(args, item);
        let narinfo = std::fs::read_to_string(target_filepath)?;
        let (narurl, narsize) = narinfo_parse(&narinfo)?;
        let new_item = NormalizedVoteItem {
            path: narurl,
            stats: NormalizedFileStats {
                score: normalize_vote(item.stats.original_score, narsize),
                original_score: item.stats.original_score,
                size: narsize,
                exists_local: false,
            },
        };
        let new_target_filepath = get_target_file_path(args, &new_item);
        if new_target_filepath.exists() {
            // Unnecessary to download, return None
            return Ok(None);
        }
        Ok(Some(new_item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_narinfo_parse() {
        let contents = r#"StorePath: /nix/store/ayaymfnf7mrwv9v9a7jkajggy2lw13w8-libavif-0.11.1
URL: nar/0lr190nraz26ki5kcl8lv64lpn3m479n61z55gazjv89lp400ic2.nar.xz
Compression: xz
FileHash: sha256:0lr190nraz26ki5kcl8lv64lpn3m479n61z55gazjv89lp400ic2
FileSize: 119676
NarHash: sha256:10j8p1hpwiab9kkwfsymckhjdgmpkx91cl6r3qkhjxm5254g2fc0
NarSize: 389520
References: 2fkl374plyncfqq325gzyp6bwgp1q0lz-libvmaf-2.3.1 59ccdxz1lvwh4lchyd4l8l9sfbqqakfm-libjxl-0.8.1 756zjmk5r6qpfsxd739x20k8xfyzxcwd-libjpeg-turbo-2.1.5.1 ayaymfnf7mrwv9v9a7jkajggy2lw13w8-libavif-0.11.1 dk6kcxxb65xhb05s6mmsa1pi3y75l4wz-libyuv-1787 hr3m53r0nhyqx80sg0bz9xjgk6jg009k-zlib-1.2.13 jmpc5b499ryzq16lzg33xj67y3irj7fp-dav1d-1.1.0 xq2dx8plnmhqy6vg56irp0ag442r4x9i-libaom-3.6.0 yaz7pyf0ah88g2v505l38n0f3wg2vzdj-glibc-2.37-8 yazs3bdl481s2kyffgsa825ihy1adn8f-gcc-12.2.0-lib yszpxj5q3j8lfxw3df0q0k2c4zmfgyg1-libpng-apng-1.6.39
Deriver: id4w8lyzpkhmfl5ixgyb093p433j61x3-libavif-0.11.1.drv
Sig: cache.nixos.org-1:k2k4/lzGGv2pgRbpSGI2sAfAq6/D+2cGCggJ7EikGpkYIftD1ss23gQmNQ7jMZP+qDhG5JPVu/bc/kBqALsgCQ=="#;
        let (url, size) = narinfo_parse(contents).unwrap();
        assert_eq!(
            url,
            "nar/0lr190nraz26ki5kcl8lv64lpn3m479n61z55gazjv89lp400ic2.nar.xz"
        );
        assert_eq!(size, 119676);
    }
}
