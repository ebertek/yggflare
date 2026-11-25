# Development and releases

[Documentation index](README.md) · [Project README](../README.md)

The image is `ghcr.io/ebertek/yggflare` . Available tags are `main` ,
`sha-FULL_COMMIT_SHA` and `vMAJOR.MINOR.PATCH` ; no `latest` tag is published. Pin the
image by digest in production.

Each published image identifies its Git revision in startup logs and through
`yggflare --version` . After an update, rerun `doctor` and `cloudflare audit` before
enabling writes.

See [AGENTS.md](../AGENTS.md) for development and test commands. CI checks Python tests,
Ruff, Black and the Docker build.

Licensed under [Apache-2.0](../LICENSE); see [NOTICE](../NOTICE).

## Source layout

```text
src/
  yggflare/           Controller, CLI, web/MCP, integrations and operations
  cloudflare/        Cloudflare audit, reconciliation and DNS
  network_inventory/ LAN discovery, identity and alerting
tests/
  application/       Controller and interface regression tests
  cloudflare/        Cloudflare fixtures and regression tests
  network_inventory/ Network discovery regression tests
docs/                 User and contributor documentation
dashboards/           Optional Grafana dashboard
scripts/              Host-side maintenance and migration helpers
```

The repository is a Docker-first application, not a published Python distribution. The source directories are added to the test import path; the Dockerfile maps them to the established `/app`, `/app/cloudflare` and `/app/network-inventory` runtime locations. This preserves existing CLI and direct diagnostic entry points. Test files are excluded from the image. Dependencies are declared in the root `requirements.txt`; tooling settings are in `pyproject.toml`.

## Local checks

From the repository root with Python 3.15 and Git installed:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install 'ruff==0.14.14' 'black==25.12.0'
export PYTHONPATH=src/yggflare:src/cloudflare:src/network_inventory
export YGGFLARE_LAN_CIDR=10.4.20.0/23
export YGGFLARE_DEVICES_CIDR=10.4.20.0/24
export YGGFLARE_DOCKER_CIDR=10.4.21.0/24
export YGGFLARE_INTERNAL_DOMAIN=ygg.nu
export YGGFLARE_EXTERNAL_DOMAIN=ebi.nu
ruff check .
black --check .
python -m compileall -q src tests
python -m unittest discover -s tests/application -p 'test_*.py'
python -m unittest discover -s tests/cloudflare -p 'test_*.py'
python -m unittest discover -s tests/network_inventory -p 'test_*.py'
docker build -t yggflare:dev .
```

The environment values above reproduce the CI fixtures; they are not production configuration. Tests are offline and use temporary files and mocked APIs. Never point development tests at live credentials or inventory state. Use the separate suites as CI does to preserve their isolation.

See [AGENTS.md](../AGENTS.md) for mandatory safety rules. The historical `scripts/import-legacy-code.sh` stages a separate ignored directory for manual review and does not overwrite maintained source.
