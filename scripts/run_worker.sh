#!/bin/sh
set -eu
celery -A crs_core.broker worker -c 1
