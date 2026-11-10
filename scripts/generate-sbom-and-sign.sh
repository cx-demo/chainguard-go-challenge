#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CHAINGUARD_IMAGE="${CHAINGUARD_IMAGE:-127.0.0.1:5001/hello-server:remediated-chainguard}"
SCRATCH_IMAGE="${SCRATCH_IMAGE:-127.0.0.1:5001/hello-server:remediated-scratch}"
SBOM_DIR="${SBOM_DIR:-$ROOT/reports/sbom}"
COSIGN_KEY="${COSIGN_KEY:-$ROOT/.keys/cosign.key}"
COSIGN_PUBLIC_KEY="${COSIGN_PUBLIC_KEY:-$ROOT/reports/signatures/cosign.pub}"

for tool in trivy cosign docker; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Required tool not found in PATH: %s\n' "$tool" >&2
    exit 1
  fi
done

for key_file in "$COSIGN_KEY" "$COSIGN_PUBLIC_KEY"; do
  if [[ ! -r "$key_file" ]]; then
    printf 'Cosign key file is not readable: %s\n' "$key_file" >&2
    exit 1
  fi
done

if [[ ! -v COSIGN_PASSWORD ]]; then
  if [[ -t 0 ]]; then
    read -r -s -p 'Cosign private-key password: ' COSIGN_PASSWORD
    printf '\n'
    export COSIGN_PASSWORD
  else
    printf 'Set COSIGN_PASSWORD or run this script in a terminal to unlock the Cosign key.\n' >&2
    exit 1
  fi
fi

public_key_tmp="$(mktemp)"
trap 'rm -f -- "$public_key_tmp"; unset COSIGN_PASSWORD' EXIT
cosign public-key --key "$COSIGN_KEY" > "$public_key_tmp"
if ! cmp -s -- "$public_key_tmp" "$COSIGN_PUBLIC_KEY"; then
  printf 'The public key derived from %s does not match %s\n' \
    "$COSIGN_KEY" "$COSIGN_PUBLIC_KEY" >&2
  exit 1
fi
rm -f -- "$public_key_tmp"

mkdir -p "$SBOM_DIR"

image_digest() {
  local image="$1"
  local repository="${image%:*}"
  local digests digest

  if [[ "$image" == *@* ]]; then
    printf '%s\n' "$image"
    return
  fi

  if ! docker image inspect "$image" >/dev/null 2>&1; then
    printf 'Container image is not available locally: %s\n' "$image" >&2
    return 1
  fi

  digests="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image")"
  while IFS= read -r digest; do
    if [[ "$digest" == "$repository@"* ]]; then
      printf '%s\n' "$digest"
      return
    fi
  done <<< "$digests"

  printf 'No pushed repository digest found for %s; push the image to its registry first.\n' \
    "$image" >&2
  return 1
}

generate_sbom() {
  local label="$1"
  local image="$2"
  local output="$SBOM_DIR/remediated-$label.cdx.json"

  if ! docker image inspect "$image" >/dev/null 2>&1; then
    printf 'Container image is not available locally: %s\n' "$image" >&2
    return 1
  fi

  printf 'Generating CycloneDX SBOM for %s\n' "$image"
  trivy image --format cyclonedx --output "$output" "$image"
}

sign_attest_and_verify() {
  local label="$1"
  local image="$2"
  local sbom="$SBOM_DIR/remediated-$label.cdx.json"
  local digest

  digest="$(image_digest "$image")"
  printf 'Signing image digest: %s\n' "$digest"
  cosign sign --yes --key "$COSIGN_KEY" --allow-http-registry "$digest"

  printf 'Attaching signed CycloneDX SBOM attestation\n'
  cosign attest --yes --key "$COSIGN_KEY" --type cyclonedx \
    --predicate "$sbom" --allow-http-registry "$digest"

  printf 'Validating image signature\n'
  cosign verify --key "$COSIGN_PUBLIC_KEY" --allow-http-registry "$digest" >/dev/null

  printf 'Validating CycloneDX SBOM attestation\n'
  cosign verify-attestation --key "$COSIGN_PUBLIC_KEY" --type cyclonedx \
    --allow-http-registry "$digest" >/dev/null

  printf 'Validated signature and SBOM attestation for %s\n' "$digest"
}

generate_sbom chainguard "$CHAINGUARD_IMAGE"
generate_sbom scratch "$SCRATCH_IMAGE"

sign_attest_and_verify chainguard "$CHAINGUARD_IMAGE"
sign_attest_and_verify scratch "$SCRATCH_IMAGE"

printf 'SBOM files written to %s\n' "$SBOM_DIR"
