# Chainguard go challenge

The repository documents my workings for the [technical challenge](./assignment/challenge.md) for position of Chainguard Solutions Engineer.

## Environment Setup

## Containerization

## Security Analysis

For runnable challenge workflows, script instructions, and expected outputs, see the [scanning guide](docs/scanning.md).

## Remediation

The govulncheck triage, minimal dependency/toolchain updates, and verification steps are documented in the [remediation guide](docs/remediation.md).

Remediated scratch and Chainguard Static multi-stage container builds, with image scan instructions, are documented in the [scanning guide](docs/scanning.md).

## Supply Chain Security

Generate per-image SBOMs, sign the remediated images, attach signed SBOM attestations, and verify them using [`scripts/generate-sbom-and-sign.sh`](scripts/generate-sbom-and-sign.sh); the workflow and OCI inspection commands are in the [supply-chain security guide](docs/supply-chain-security.md).

## Deployment

Build and run the remediated Chainguard image as a standalone container or deploy it to the local Kubernetes cluster using the [deployment guide](docs/deployment.md) and [manifest](k8s/remediated-chainguard.yaml). The guide includes Trivy Dockerfile and Kubernetes configuration scans.

## References
hello-melange-apko [[1]]  

[1]:https://github.com/chainguard-dev/hello-melange-apko
