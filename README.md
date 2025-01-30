# yukina

YUKI-based Next-generation Async-cache

## Approach (Simplified)

1. Get nginx log for some days (7 days by default), filter out all interesting requests, collect their "popularity"
2. Get local interesting files metadata
3. Remove files that are not "popular", try to get new files while under the limit

## TODOs

- [x] Add examples in yuki configuration
- [x] Eliminate the need of `lstat()`s in stage2 (a bit slow for nix-channels)

## Nginx configuration

An example, assuming that access_log is in default combined format:

```nginx
location /pypi/web/ {
    rewrite ^/pypi/web/(.*)$ /pypi/$1 permanent;
}

location ~ ^/pypi/simple/[^/]*([A-Z]|_|\.)[^/]* {
    # local package_name = ngx.var.uri:match("/pypi/simple/(.+)")
    # if package_name and package_name ~= "index.html" then
    #     -- Normalize the package name per PEP 503
    #     local normalized = package_name:gsub("[-_.]+", "-"):lower()
    #     return ngx.redirect("/pypi/simple/" .. normalized, ngx.HTTP_MOVED_TEMPORARILY)
    # end
    rewrite_by_lua_file /etc/nginx/lua/pypi_normalize.lua;
}

location ~ ^/pypi/[^/]*([A-Z]|_|\.)[^/]*/json {
    # local package_name = ngx.var.uri:match("/pypi/(.+)/json")
    # if package_name then
    #     -- Normalize the package name per PEP 503
    #     local normalized = package_name:gsub("[-_.]+", "-"):lower()
    #     return ngx.redirect("/pypi/" .. normalized .. "/json", ngx.HTTP_MOVED_TEMPORARILY)
    # end
    rewrite_by_lua_file /etc/nginx/lua/pypi_normalize.lua;
}

location ~ ^/pypi/[^/]+/json$ {
    access_log /var/log/nginx/cacheproxy/pypi.log;
    rewrite ^/pypi/([^/]+)/json$ /pypi/json/$1 break;
    types { }
    default_type "application/json; charset=utf-8";
}

location ~ ^/pypi/simple {
    access_log /var/log/nginx/cacheproxy/pypi.log;
    # conf.d/pypi.conf:
    # map $http_accept $pypi_mirror_suffix {
    #     default ".html";
    #     "~*application/vnd\.pypi\.simple\.v1\+json" ".v1_json";
    #     "~*application/vnd\.pypi\.simple\.v1\+html" ".v1_html";
    #     "~*text/html" ".html";
    # }

    index index$pypi_mirror_suffix index.html;
    types {
        application/vnd.pypi.simple.v1+json v1_json;
        application/vnd.pypi.simple.v1+html v1_html;
        text/html html;
    }
    default_type "text/html";
    # try_files $uri$pypi_mirror_suffix $uri $uri/ @pypi_302;
    try_files $uri$pypi_mirror_suffix $uri $uri/ =404;
}

location /pypi/packages/ {
    access_log /var/log/nginx/cacheproxy/pypi.log;
    try_files $uri $uri/ @pypi_302;
}

location /pypi/json/ {
    autoindex off;
}

location @pypi_302 {
    access_log /var/log/nginx/cacheproxy/pypi.log;
    # -> $scheme://mirrors.example.com/pypi/...
    rewrite ^/pypi/(.*)$ $scheme://mirrors.example.com/pypi/web/$1 redirect;
}

location /anaconda/cloud/ {
    access_log /var/log/nginx/cacheproxy/anaconda.log;
    try_files $uri $uri/ @anaconda_302;
}

location @anaconda_302 {
    access_log /var/log/nginx/cacheproxy/anaconda.log;
    # -> $scheme://mirrors.example.com/anaconda/...
    return 302 $scheme://mirrors.example.com$request_uri;
}

location /nix-channels/store/ {
    access_log /var/log/nginx/cacheproxy/nix-channels.log;
    # disable autoindex, there are TOO MANY files
    autoindex off;
    try_files $uri $uri/ @nixchannels_404;
}

location @nixchannels_404 {
    access_log /var/log/nginx/cacheproxy/nix-channels.log;
    # just return 404, nix knows how to handle it
    return 404;
}

location /flathub/objects/ {
    access_log /var/log/nginx/cacheproxy/flathub.log;
    autoindex off;
    try_files $uri $uri/ @flathub_302;
}

location @flathub_302 {
    access_log /var/log/nginx/cacheproxy/flathub.log;
    rewrite ^/flathub/(.*)$ $scheme://dl.flathub.org/repo/$1 redirect;
}
```

## Yuki configuration

See [examples](examples/).

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
          Don't really download or remove anything, just show what would be done. (HEAD requests are still sent.)
      --log-duration <LOG_DURATION>
          Log items to check. Access log beyond log_duration would be ignored [default: 7d]
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
      --remote-sizedb <REMOTE_SIZEDB>
          A kv database of file size to speed up stage3 in case yukina would run frequently
      --local-sizedb <LOCAL_SIZEDB>
          Another kv database of file size, but for local files, to skip lstat()s
      --size-database-ttl <SIZE_DATABASE_TTL>
          Size database Miss TTL [default: 2d]
      --filesize-limit <FILESIZE_LIMIT>
          Single file size limit, files larger than this will NOT be counted/downloaded [default: 4g]
      --min-vote-count <MIN_VOTE_COUNT>
          Minimum vote count to consider a file as a candicate [default: 2]
      --retry <RETRY>
          Retry count for each request [default: 3]
      --extension <EXTENSION>
          Extension for specific repo types [possible values: nix-channels]
      --aggressive-removal
          Aggressively remove all files not accessed during log_duration, instead of just keep it within threshold
      --gc-only
          Don't download anything, just remove unpopular files
  -h, --help
          Print help
  -V, --version
          Print version
```

"Extension" is a special option for specific repo types:

- nix-channels: This extension would parse narinfo file and add the blob urls to the download list.

`kv` is a very simple wrapper around `sled` (same as the version yukina uses). KV tool:

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

## Does it Work Well in Practice?

See [stats](stats/).

## Naming

"Yukina" means "YUKI-based Next-generation Async-cache"... OK, you might not find that very convincing, neither do I. Actually, this name comes from [Yukina Minato](https://en.wikipedia.org/wiki/List_of_BanG_Dream!_characters#Yukina_Minato), the vocalist of Roselia from *BanG Dream!* series.

And [yuki](https://github.com/ustclug/yuki) is a mirror management tool used inhouse in USTC mirrors (another choice besides [tunasync](https://github.com/tuna/tunasync), try it if you need!). This program actually does not require yuki (yuki examples are given for your convenience), but I just want to make a pun.

## Acknowledgements

I would like to give special thanks to [SeanChao/mirror-cache](https://github.com/SeanChao/mirror-cache), which is sponsored in OSPP 2021. Though this project is finally not used by us, it has "forced" me to rethink the design of a repoistory caching system, and I have learned a lot from it. If you need a more general-purpose cache, you might want to try it.
