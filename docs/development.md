# Development and releases

[Documentation index](README.md) · [Project README](../README.md)

The image is `ghcr.io/ebertek/yggflare`, with `main`,
`sha-FULL_COMMIT_SHA` and `vMAJOR.MINOR.PATCH` tags. Pin a digest in production.

CI runs the Python suites, Ruff, Black and a Docker build.
See [AGENTS.md](../AGENTS.md) for contributor rules.

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

The Dockerfile maps source directories to `/app`, `/app/cloudflare` and
`/app/network-inventory`. Tests are excluded from the image. Dependencies
are in `requirements.txt`; tooling configuration is in `pyproject.toml`.

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

The example environment reproduces CI fixtures, not a deployment. Tests use
mocked APIs and temporary files. Run the three suites separately and never
use live credentials or inventory.

## Release process

1. Merge reviewed changes to `main` and verify CI and Lint.
2. Publish an approved `vMAJOR.MINOR.PATCH` tag at the reviewed commit.
3. Confirm GHCR publication and the image's source revision.
4. Publish [release notes](https://github.com/ebertek/yggflare/releases).
5. Pin the verified digest in the deployment and run
   [deployment acceptance](operations.md#deployment-acceptance).

The publish workflow repeats lint and tests before pushing. A stable tag at
current main HEAD also updates `:main`; a historical stable tag does not.
Never move a published tag.
