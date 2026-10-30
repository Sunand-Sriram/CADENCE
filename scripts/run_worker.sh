#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PATH="$REPO_ROOT/.venv/bin:$PATH"
export PATH
celery -A crs_core.broker worker -c 1 --loglevel=info --pool=solo
