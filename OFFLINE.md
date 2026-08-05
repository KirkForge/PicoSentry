# Offline / Air-Gapped Operation

PicoSentry runs fully offline. No telemetry, no phone-home, no network required.

## Quick Start

```bash
pip install picosentry
picosentry scan ./project          # works offline, no API keys needed
```

The built-in corpus and rules ship with the package. First scan works without internet.

## Corpus Updates (Offline)

Export a corpus pack on a networked machine, transfer it to the air-gapped host:

```bash
# Networked machine
picosentry corpus export /path/to/pack.tgz

# Air-gapped host
picosentry corpus import /path/to/pack.tgz
```

Or use `picosentry update --offline /path/to/pack.tgz` to update both corpus and rules from a single archive.

## Advisory Packs

Download OSV-format advisory data on a connected machine, then load locally:

```bash
# Networked machine
picosentry advisories download -o advisories.db

# Air-gapped host
picosentry advisories load advisories.db
```

Scan with `--advisory-db advisories.db` to use the local database.

## Air-Gapped Docker Deployment

```bash
# Networked machine
docker pull ghcr.io/kirkforge/picosentry:latest
docker save picosentry:latest -o picosentry.tar

# Transfer via USB, copy to air-gapped host
docker load -i picosentry.tar
docker run --rm --network none picosentry:latest scan /project
```

The `--network none` flag (or Docker `--no-network`) ensures zero outbound connectivity.

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