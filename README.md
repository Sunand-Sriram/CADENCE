# CADENCE CRS

CADENCE is a crash-reproduction system (CRS) built around the existing
`crs_core` schemas, broker, and agents modules. The scaffold includes target,
crash, evidence, and mock-data locations plus scripts for operating a Celery
worker.

## Mock mode

The checked-in `.env.example` documents the configuration, while local `.env`
defaults to `CRS_LLM_MODE=mock`. After installing dependencies into `.venv`,
load the environment and start the worker:

```sh
source .venv/bin/activate
set -a; . ./.env; set +a
./scripts/run_worker.sh
```

The target project belongs in `targets/target/`. Build and test commands are
configured by `CRS_BUILD_CMD` and `CRS_TEST_CMD`.
