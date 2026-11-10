#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$ROOT/.tools/go/bin:$HOME/go/bin:$PATH"

SINGLE_IMAGE="${SINGLE_IMAGE:-127.0.0.1:5001/hello-server:single-stage}"
MULTI_IMAGE="${MULTI_IMAGE:-127.0.0.1:5001/hello-server:multi-stage}"
SCAN_DIR="${SCAN_DIR:-$ROOT/reports/scans/original}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"

for tool in docker trivy govulncheck python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Required tool not found in PATH: %s\n' "$tool" >&2
    exit 1
  fi
done

mkdir -p "$SCAN_DIR"
rm -f -- "$SCAN_DIR/single-stage.govulncheck.json" \
  "$SCAN_DIR/multi-stage.govulncheck.json"

for image in "$SINGLE_IMAGE" "$MULTI_IMAGE"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    printf 'Container image is not available locally: %s\n' "$image" >&2
    exit 1
  fi
done

scan_image() {
  local label="$1"
  local image="$2"
  printf 'Trivy image scan: %s\n' "$image"
  trivy --cache-dir "$TRIVY_CACHE_DIR" image --scanners vuln --format json \
    --output "$SCAN_DIR/$label.trivy.json" "$image"
}

scan_image single-stage "$SINGLE_IMAGE"
scan_image multi-stage "$MULTI_IMAGE"

python3 - "$TRIVY_CACHE_DIR/db/metadata.json" \
  "$SCAN_DIR/single-stage.trivy.json" "$SCAN_DIR/multi-stage.trivy.json" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path

metadata_path = Path(sys.argv[1])
try:
    database = json.loads(metadata_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"Cannot read Trivy vulnerability database metadata {metadata_path}: {error}")

database_info = {
    "source": "ghcr.io/aquasecurity/trivy-db:2",
    "schemaVersion": database.get("Version"),
    "updatedAt": database.get("UpdatedAt"),
    "downloadedAt": database.get("DownloadedAt"),
    "nextUpdate": database.get("NextUpdate"),
}
if not database_info["updatedAt"] or not database_info["schemaVersion"]:
    raise SystemExit(f"Incomplete Trivy vulnerability database metadata: {metadata_path}")

for report_arg in sys.argv[2:]:
    report_path = Path(report_arg)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Cannot read Trivy report {report_path}: {error}")
    report.setdefault("Trivy", {})["VulnerabilityDB"] = database_info
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=report_path.parent, delete=False
        ) as temp:
            temp_path = Path(temp.name)
            json.dump(report, temp, indent=2)
            temp.write("\n")
        os.replace(temp_path, report_path)
    except OSError as error:
        if temp_path:
            temp_path.unlink(missing_ok=True)
        raise SystemExit(f"Cannot update Trivy report metadata {report_path}: {error}")
PY

printf 'govulncheck source reachability scan: %s\n' "$ROOT/sources/original"
govulncheck -json -C "$ROOT/sources/original" ./... \
  > "$SCAN_DIR/source.govulncheck.json"

printf 'JSON reports written to %s\n' "$SCAN_DIR"
