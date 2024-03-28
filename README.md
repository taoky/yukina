# yukina

YUKI-based Next-generation Async-cache

## Approach

1. Get nginx log for 7 days, filter out all interesting requests, collect their "popularity"
2. Get local interesting files metadata
3. Remove files that are not "popular", try to get new files while under the limit
