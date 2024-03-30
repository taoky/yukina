# yukina

YUKI-based Next-generation Async-cache

## Approach (Simplified)

1. Get nginx log for 7 days, filter out all interesting requests, collect their "popularity"
2. Get local interesting files metadata
3. Remove files that are not "popular", try to get new files while under the limit

## Usage

```console
$ cargo run -- --help
YUKI-based Next-generation Async-cache

Usage: yukina [OPTIONS] --name <NAME> --log-path <LOG_PATH> --repo-path <REPO_PATH> --size-limit <SIZE_LIMIT> --url <URL>

Options:
      --name <NAME>
          Repo name, used for finding log file and downloading from remote
      --log-path <LOG_PATH>
          Directory of nginx log
      --repo-path <REPO_PATH>
          Directory of repo
      --dry-run
          Don't really download or remove anything, just show what would be done
      --user-agent <USER_AGENT>
          User agent to use [default: "yukina (https://github.com/taoky/yukina)"]
      --size-limit <SIZE_LIMIT>
          Size limit of your repo
      --filter <FILTER>
          Filter for urls and file paths you interested in (usually blobs of the repo)
      --url <URL>
          URL of the remote repo
      --strip-prefix <STRIP_PREFIX>
          Optional prefix to strip from the path after the repo name
      --size-database <SIZE_DATABASE>
          A kv database of file size to speed up stage3 in case yukina would run frequently
      --size-database-ttl <SIZE_DATABASE_TTL>
          Size database Miss TTL [default: 2d]
      --filesize-limit <FILESIZE_LIMIT>
          [default: 4g]
  -h, --help
          Print help
  -V, --version
          Print version
```

KV tool:

```console
$ cargo run --bin kv -- --help
Usage: kv <COMMAND>

Commands:
  get     
  remove  
  scan    
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Naming

"Yukina" means "YUKI-based Next-generation Async-cache"...OK, you might not find that very convincing, neither do I. Actually, this name comes from [Yukina Minato](https://en.wikipedia.org/wiki/List_of_BanG_Dream!_characters#Yukina_Minato), the vocalist of Roselia from *BanG Dream!* series.

And [yuki](https://github.com/ustclug/yuki) is a mirror management tool used inhouse in USTC mirrors (another choice besides [tunasync](https://github.com/tuna/tunasync), try it if you need!). This program actually does not require yuki, but I just want to make a pun.
