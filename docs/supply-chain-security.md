# SBOMs, signatures, and attestations

This guide covers generating Trivy SBOMs for the remediated images, signing the images with Cosign, attaching signed SBOM attestations to the registry, and validating the artifacts.

## Generate, sign, and validate

Run the workflow from the repository root:

```sh
./scripts/generate-sbom-and-sign.sh
```

By default, the script uses `127.0.0.1:5001/hello-server:remediated-chainguard` and `127.0.0.1:5001/hello-server:remediated-scratch`. Both images must already be built and pushed to the registry. The script generates these local CycloneDX SBOM files:

- `reports/sbom/remediated-chainguard.cdx.json`
- `reports/sbom/remediated-scratch.cdx.json`

It signs each image by its immutable registry digest, attaches the corresponding CycloneDX SBOM as a signed attestation, and verifies both artifacts. Override image tags, output directory, or key paths with `CHAINGUARD_IMAGE`, `SCRATCH_IMAGE`, `SBOM_DIR`, `COSIGN_KEY`, and `COSIGN_PUBLIC_KEY`.

The default private key at `.keys/cosign.key` is encrypted. When run in a terminal the script prompts for its password without echoing it. For non-interactive use, set `COSIGN_PASSWORD` through a secure secret mechanism; do not put the password in the script or commit it. The script confirms that the unlocked private key matches `reports/signatures/cosign.pub` before signing. It uses `--allow-http-registry` for this repository's local HTTP test registry; do not use that option with production registries.

## Inspect and verify OCI artifacts

The script prints the immutable image digest it signs. Use those digests to inspect and verify the registry artifacts independently:

```sh
for IMAGE_DIGEST in \
  127.0.0.1:5001/hello-server@sha256:f17e0ab39c5ee6aa0373cf3fdb8949c520cc626aab6ec7486d2672b285fb7981 \
  127.0.0.1:5001/hello-server@sha256:04eba75e5a6e1051d05828d979870b456bf7c6230d8626094d0962871e5f35e4
do
  # List the signature and SBOM OCI referrers stored alongside the image.
  cosign tree --allow-http-registry "$IMAGE_DIGEST"

  # Verify the image signature, then verify and decode its signed SBOM predicate.
  cosign verify --key reports/signatures/cosign.pub \
    --allow-http-registry "$IMAGE_DIGEST"
  cosign verify-attestation --key reports/signatures/cosign.pub \
    --type cyclonedx --allow-http-registry "$IMAGE_DIGEST" \
    | jq -r 'if type == "array" then .[].payload else .payload end' \
    | base64 --decode | jq '.predicate'
done
```

`cosign tree` reads the registry's OCI referrers and displays the signature artifact and CycloneDX attestation associated with each image digest. `cosign verify` checks the image signature against the public key. `cosign verify-attestation` validates the attestation signature and predicate type; the `jq`/`base64` pipeline decodes and displays its SBOM predicate. The digest examples above are the current local-registry images; replace them with the digests printed by the script after rebuilding or pushing new images.

The JSON files in `reports/sbom/` are convenient local copies. The signed attestations are stored as OCI artifacts in the registry and refer to the image digest.

## Registry verification results

The workflow was executed and the registry artifacts were independently inspected and verified on 2026-11-09:

| Image | Signed image digest | Attestation predicate |
|---|---|---|
| `remediated-chainguard` | `sha256:f17e0ab39c5ee6aa0373cf3fdb8949c520cc626aab6ec7486d2672b285fb7981` | CycloneDX 1.7, 23 components |
| `remediated-scratch` | `sha256:04eba75e5a6e1051d05828d979870b456bf7c6230d8626094d0962871e5f35e4` | CycloneDX 1.7, 19 components |

For both images, `cosign tree` showed a signature referrer and a CycloneDX referrer. `cosign verify` and `cosign verify-attestation` succeeded with `reports/signatures/cosign.pub`; the attestation predicates decoded successfully and their component counts matched the local SBOM files.
