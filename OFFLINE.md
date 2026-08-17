# Offline / Air-Gapped Operation

PicoSentry runs fully offline. No telemetry, no phone-home, no network required.

## Quick Start

```bash
pip install picosentry
picosentry scan ./project          # works offline, no API keys needed
```

The built-in corpus and rules ship with the package. First scan works without internet.

## Corpus Updates (Offline)

Export a corpus pack (JSON) on a networked machine, transfer it to the
air-gapped host. Note: there is no single-archive "update from pack" command —
`picosentry update --offline` only refuses network access and takes no pack
argument; offline pack updates go through `corpus import`.
```bash
# Networked machine
picosentry corpus export /path/to/pack.json

# Air-gapped host
picosentry corpus import /path/to/pack.json
```

## Advisory Packs

A bundled advisory snapshot (npm critical advisories) ships with the package
(`picosentry/scan/corpus/advisories/`). For a fuller dataset, fetch the
advisory database on a networked machine and transfer the output directory —
the fetch command lives on the inner scan CLI (`picosentry advisories` is not
a unified-CLI subcommand):

```bash
# Networked machine
python -m picosentry.scan advisories fetch <advisory-bundle-url> -o advisories/

# Air-gapped host — scan with the local database
picosentry scan ./project --advisory-db /path/to/advisories/
```

Online OSV queries (`api.osv.dev`) happen only in connected intelligence mode
(`--intelligence connected`), which requires network by design.

## Air-Gapped Docker Deployment

```bash
# Networked machine
docker pull docker.io/kirkforge/picodome:latest
docker save kirkforge/picodome:latest -o picodome.tar

# Transfer via USB, copy to air-gapped host
docker load -i picodome.tar
docker run --rm --network none kirkforge/picodome:latest scan /project
```

The `--network none` flag ensures zero outbound connectivity for the container.

## Deterministic Output

Same input + same policy = same SHA-256. No timestamps, no randomness.

```bash
# Verify byte-identical output across two runs
picosentry scan ./project --verify-determinism
# Exit 0: deterministic. Exit 4: results differ.

# Produce byte-stable JSON (no timestamps, no timing metadata)
picosentry scan ./project --deterministic-output --format json -o report.json
```

Use `--verify-determinism` in CI for audit compliance.