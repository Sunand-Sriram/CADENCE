#!/bin/sh
set -eu

find crashes -mindepth 1 -maxdepth 1 ! -name seed_crash -exec rm -rf {} +
find evidence -mindepth 1 -maxdepth 1 -exec rm -rf {} +

if docker exec crs-redis redis-cli --scan --pattern 'crs:*' | \
    xargs -r docker exec -i crs-redis redis-cli del; then
    redis_result="cleared crs:* keys"
else
    docker exec crs-redis redis-cli flushdb
    redis_result="flushdb fallback used"
fi

echo "reset complete: crashes/evidence cleared; $redis_result"
