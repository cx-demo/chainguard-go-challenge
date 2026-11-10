# Technology Stack Selection

## Container builds

**Docker Engine with Buildx** was chosen as the container engine and image builder because it provides a single familiar workflow for building and running the challenge images, the local OCI registry, and kind's node containers. Buildx uses BuildKit and supports the required single- and multi-stage Dockerfile builds, with image output compatible with the local registry and OCI tooling. The installed versions are Docker Engine 29.9.3 and Buildx 0.38.1; the active builder uses the `docker` driver and currently reports `linux/arm64`. That is sufficient for the present environment, but multi-platform builds or tests on other architectures should not be assumed validated.

## Vulnerability analysis and SBOMs

**Trivy** covers two explicit deliverables with one tool: scanning container images for OS and application-package vulnerabilities, and generating SBOMs. Keeping both outputs in the same workflow makes it easier to relate a finding to the image inventory. The scanner version is recorded in [`../reports/environment/trivy.txt`](../reports/environment/trivy.txt).

**govulncheck** complements image scanning with Go-specific analysis. It checks Go code and dependencies against Go vulnerability data and reports whether vulnerable symbols are reachable from the application, which helps prioritize findings beyond a package/version match. It does not replace Trivy's coverage of the full container, including OS packages. Its build details are recorded in [`../reports/environment/govulncheck-build.txt`](../reports/environment/govulncheck-build.txt).

## Local Kubernetes and registry

**kind** provides a Kubernetes cluster locally, avoiding a cloud dependency while still allowing the deployment manifests and image-pull workflow to be exercised. This is a practical challenge environment, not a substitute for testing production cluster operations. The selected kind version is recorded in [`../reports/environment/kind.txt`](../reports/environment/kind.txt).

**OCI registry — `registry:3`** was selected as a small, straightforward local registry for the challenge's push, pull, and signing workflow, without requiring a hosted service or a separate registry product. The registry container is attached to kind's Docker network so cluster nodes can reach it; its port is also mapped to `127.0.0.1:5001` for host-side use. Strictly, this is a Docker container alongside kind, not a Kubernetes workload deployed inside the cluster. The recorded container configuration is in [`../reports/environment/registry-container.json`](../reports/environment/registry-container.json). This setup is convenient for local testing, but it does not provide production registry features or establish durable storage, access control, or TLS.

## Image signing

**Cosign** provides OCI-compatible image signing and verification, addressing the requirement to sign the images pushed to the local registry. Using it makes integrity verification part of the image workflow rather than relying only on tags. The signing key and its trust policy must be protected and verified deliberately; a valid signature alone does not prove that an image was built from trusted source or through a trusted process. The installed version is recorded in [`../reports/environment/cosign.txt`](../reports/environment/cosign.txt).

Together, these choices separate complementary checks: Docker/Buildx builds and runs images, Trivy inventories and scans them, govulncheck assesses Go vulnerability reachability, kind tests Kubernetes deployment, the local registry supports the image push/pull path, and Cosign checks image integrity and signing identity. At the time of this selection, challenge image builds, scans, signatures, and deployment validation remained to be documented as they were performed.
