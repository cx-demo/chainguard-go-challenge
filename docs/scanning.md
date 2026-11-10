# Container vulnerability scanning

This guide covers running the repository's container scans and generating the HTML findings reports. Run the commands from the repository root.

## Prerequisites

- Docker with both challenge images built and available locally.
- Trivy and govulncheck installed and available on `PATH`. The scan script also checks `.tools/go/bin` and `$HOME/go/bin` for govulncheck.
- Python 3 to generate the HTML reports.

The default image tags are `127.0.0.1:5001/hello-server:single-stage` and `127.0.0.1:5001/hello-server:multi-stage`. Build the images before scanning if either tag is missing.

## Run scans and generate reports

```sh
./scripts/scan-containers.sh
./scripts/generate-scan-reports.py \
  --trivy-report "Single-stage=reports/scans/original/single-stage.trivy.json" \
  --trivy-report "Multi-stage=reports/scans/original/multi-stage.trivy.json" \
  --govulncheck-report reports/scans/original/source.govulncheck.json
```

`scan-containers.sh` runs Trivy once against each image and govulncheck once against `sources/original` in source mode. Govulncheck's source reachability results are useful for triage, but do not prove exploitability in either image.

Original scan outputs are written to `reports/scans/original/`. Remediated scan artifacts and HTML reports are kept separately in `reports/scans/remediated/`.

The original source is the scan baseline. To scan the separate remediated copy with the same govulncheck mode, run `govulncheck -json -C "$PWD/sources/remediated" ./...` and save its output to a separate report file. See the [remediation guide](remediation.md) for how to interpret and verify that result.

## Remediated container builds

The original single-stage image includes its Go toolchain and Debian 11.6 OS packages at runtime. The scan warns that Debian 11.6 is unsupported, so its OS findings are not a reliable basis for incremental package upgrades. The multi-stage builds below compile from the already-remediated Go module and leave the compiler/toolchain out of the final image. The scratch variant has no OS package database; the Chainguard variant uses the minimal Chainguard Static runtime.

Build both variants from the remediated source context:

```sh
docker build --pull -f docker/Dockerfile.multistage.remediated \
  -t hello-server:remediated-scratch sources/remediated
docker build --pull -f docker/Dockerfile.multistage.chainguard \
  -t hello-server:remediated-chainguard sources/remediated
```

The Chainguard reference is pinned to the multi-platform manifest-list digest used for the scan. Updating the base requires deliberately refreshing that digest, rebuilding, and rescanning.

Scan each final image independently and keep the JSON reports distinct from the original reports:

```sh
trivy image --scanners vuln --format json \
  --output reports/scans/remediated/scratch.trivy.json \
  hello-server:remediated-scratch
trivy image --scanners vuln --format json \
  --output reports/scans/remediated/chainguard.trivy.json \
  hello-server:remediated-chainguard
```

Check `Results[].Vulnerabilities` in each Trivy report, not only the console summary. Trivy does not report OS packages for `scratch`; its Go binary findings still need to be zero. For Chainguard Static, review both OS and Go binary results. Mutable base-image tags can change between builds; the Chainguard Dockerfile pins the resolved manifest-list digest, which must be deliberately refreshed and rescanned to pick up later fixes.

## Supply-chain artifacts

SBOM generation, image signing, signed attestations, OCI registry inspection, and verification are documented in the [supply-chain security guide](supply-chain-security.md).

## Remediated scan results

The remediated images were built from `sources/remediated` and scanned with Trivy 0.76.2 on 2026-11-09. Both scans reported zero vulnerabilities:

| Image | Runtime contents | Trivy findings |
|---|---|---:|
| `hello-server:remediated-scratch` | App binary only; no OS package database | 0 |
| `hello-server:remediated-chainguard` | Chainguard Static (Wolfi) and app binary | 0 |

The JSON evidence is in `reports/scans/remediated/scratch.trivy.json` and `reports/scans/remediated/chainguard.trivy.json`. Govulncheck v1.9.0 also reported zero source findings for the remediated module; its output is in `reports/scans/remediated/source.govulncheck.json`. Both containers were smoke-tested and returned `Hello World!`.

**Database timestamp limitation:** the Trivy database metadata used for these scans says it was updated on 2026-11-10, and the govulncheck database says 2026-11-11—both later than the scan date. Treat these zero-finding results as provisional until the database timestamps and scanner environment are reconciled and the images are rescanned with a contemporaneous, trusted database. A zero-finding scan is also time-bound; rebuild and rescan after base-image or vulnerability-database updates.

The report generator accepts input file paths as arguments rather than assuming fixed report filenames. Supply each Trivy report as a repeatable `--trivy-report "LABEL=PATH"` option; the label is used to identify that report in the HTML. Supply the govulncheck JSON stream with `--govulncheck-report PATH`. By default, the HTML files use the conventional names `trivy-comparison.html` and `govulncheck-trivy-correlation.html` in the first Trivy report's directory (or in the directory specified with `--output-dir`). Override either filename or its full path with `--comparison-output PATH` or `--correlation-output PATH`.

If the govulncheck source scan is for a tree other than `sources/original`, pass its repository-relative directory with `--source-dir`. This sets the source label and application-frame links in the correlation report; it defaults to `sources/original`.

The scan script records Trivy's vulnerability-database source, schema version, last-updated time, download time, and next-update time in each Trivy JSON report. It reads the metadata from Trivy's cache directory (`$HOME/.cache/trivy` by default); override the location with `TRIVY_CACHE_DIR` if needed. Govulncheck JSON records its database URL and last-modified timestamp.

The HTML generator reads the JSON reports from `reports/scans/original/` or `reports/scans/remediated/` and writes two self-contained, offline reports beside the first Trivy input:

- `reports/scans/original/trivy-comparison.html` or `reports/scans/remediated/trivy-comparison.html` summarizes the selected images. Each image has its own collapsible details section with findings grouped under collapsible package/library headings. Search, severity, package/library type, and fix-status filters are available within each image section.
- `reports/scans/original/govulncheck-trivy-correlation.html` or `reports/scans/remediated/govulncheck-trivy-correlation.html` shows a confidence summary directly above each Trivy image report's detailed findings. Confidence is independent from scanner severity and is scored using four matching signals: govulncheck symbol reachability, exact package/module name, package version, and exact CVE ID. High means 4/4 signals match, Moderate 3/4, Limited 1-2/4, and Unmatched 0/4. Findings are grouped under collapsible package/library headings within each report and include govulncheck source call paths when available. Paths link to the source directory specified with `--source-dir`; CVE and govulncheck advisory links, matched versions, and filters for search, confidence, severity, package type, reachability, and fix status are also provided.

The correlation report only compares Trivy findings for the `hello-server` binary to the govulncheck source scan. Trivy findings for the single-stage image's OS packages and Go toolchain are still included in the Trivy comparison but are not matched to application source findings.

## Outputs

The scan command produces the following JSON files:

- `reports/scans/original/single-stage.trivy.json`
- `reports/scans/original/multi-stage.trivy.json`
- `reports/scans/original/source.govulncheck.json`
- `reports/scans/remediated/scratch.trivy.json`
- `reports/scans/remediated/chainguard.trivy.json`
- `reports/scans/remediated/source.govulncheck.json`
- `reports/scans/remediated/trivy-comparison.html`
- `reports/scans/remediated/govulncheck-trivy-correlation.html`

The report-generation command writes:

- `reports/scans/original/trivy-comparison.html`
- `reports/scans/original/govulncheck-trivy-correlation.html`

## Configuration and interpretation

Override image tags or the scan output directory using environment variables:

```sh
SINGLE_IMAGE=example/app:single \
MULTI_IMAGE=example/app:multi \
SCAN_DIR=/tmp/app-scans/original \
./scripts/scan-containers.sh

./scripts/generate-scan-reports.py \
  --trivy-report "Single-stage=/tmp/app-scans/original/single-stage.trivy.json" \
  --trivy-report "Multi-stage=/tmp/app-scans/original/multi-stage.trivy.json" \
  --govulncheck-report /tmp/app-scans/original/source.govulncheck.json
```

To ingest a different set of files, pass their paths directly and provide a descriptive label for each Trivy report. For example, an additional report can be included by adding another `--trivy-report "LABEL=PATH"` option. Use `--output-dir /path/to/html` to choose a separate default destination for the HTML files, or pass explicit output paths:

```sh
./scripts/generate-scan-reports.py \
  --trivy-report "Release=/tmp/release.trivy.json" \
  --govulncheck-report /tmp/source.govulncheck.json \
  --comparison-output /tmp/reports/release-comparison.html \
  --correlation-output /tmp/reports/release-correlation.html
```

Explicit output paths take precedence over `--output-dir`; their parent directories are created if needed. When re-running scans, the scan script replaces the corresponding JSON outputs in `SCAN_DIR`. It also removes legacy per-image govulncheck JSON files if present, since govulncheck runs only against the source tree.

Both HTML reports display scanner versions and vulnerability-database provenance. The Trivy comparison shows scanner version, DB source/schema, DB updated/downloaded/next-update times, and image scan time for each report. The correlation report shows this alongside govulncheck's scanner version, Go version, scan mode/level, DB URL, and DB last-modified timestamp. govulncheck JSON has no scan timestamp, which is marked as unavailable. Compare database timestamps before making conclusions: Trivy and govulncheck may have used databases updated at different times. Vulnerability totals count scanner findings, not necessarily unique exploitable defects. A fixed version indicates that Trivy reported a fix; it does not automatically mean the image has been remediated. The single-stage image uses Debian 11.6, which Trivy reports as unsupported, so OS vulnerability detection may be insufficient.
