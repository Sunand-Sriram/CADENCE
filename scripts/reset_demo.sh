#!/bin/sh
set -eu

find crashes -mindepth 1 -maxdepth 1 ! -name seed_crash -exec rm -rf {} +
find evidence -mindepth 1 -maxdepth 1 -exec rm -rf {} +

redis_result="Redis keys were not cleared"

if command -v redis-cli >/dev/null 2>&1; then
    redis_cli() {
        if [ -n "${CRS_REDIS_URL:-}" ]; then
            redis-cli -u "$CRS_REDIS_URL" "$@"
        else
            redis-cli -h 127.0.0.1 -p 6379 "$@"
        fi
    }
    redis_manual="redis-cli -u \"\${CRS_REDIS_URL:-redis://127.0.0.1:6379}\" --scan --pattern 'crs:*'"
elif command -v docker >/dev/null 2>&1 &&
    docker ps --filter name=crs-redis --format '{{.Names}}' 2>/dev/null |
    grep -qx 'crs-redis'; then
    redis_cli() {
        docker exec crs-redis redis-cli "$@"
    }
    redis_manual="docker exec crs-redis redis-cli --scan --pattern 'crs:*'"
else
    echo "WARNING: Redis keys were not cleared; no host redis-cli or running crs-redis container was found." >&2
    echo "         Run redis-cli --scan --pattern 'crs:*' and delete each returned key (or flushdb if disposable)." >&2
    echo "reset complete: crashes/evidence cleared; $redis_result"
    exit 0
fi

if keys=$(redis_cli --scan --pattern 'crs:*'); then
    clear_ok=true
    if [ -n "$keys" ]; then
        while IFS= read -r key; do
            [ -n "$key" ] || continue
            if ! redis_cli del "$key" >/dev/null; then
                clear_ok=false
                break
            fi
        done <<EOF
$keys
EOF
    fi
    if [ "$clear_ok" = true ]; then
        redis_result="cleared crs:* keys"
    fi
fi

if [ "$redis_result" != "cleared crs:* keys" ]; then
    if redis_cli flushdb >/dev/null; then
        redis_result="flushdb fallback used"
    else
        echo "WARNING: Redis keys were not cleared; scan and flushdb both failed." >&2
        echo "         Clear them manually with: $redis_manual" >&2
    fi
fi

echo "reset complete: crashes/evidence cleared; $redis_result"
