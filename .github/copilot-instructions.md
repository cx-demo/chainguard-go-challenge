# Chainguard Solutions Engineer Challenge

This workspace is for completing the Chainguard Solutions Engineer technical challenge described in [`assignment/challenge.md`](../assignment/challenge.md). Treat that brief as the source of truth for scope and deliverables. Help the user work through the challenge, explaining important technical decisions and tradeoffs.

## Workspace structure

Keep challenge artifacts in the appropriate directory:

```text
.github/
  copilot-instructions.md   Workspace guidance for Copilot
assignment/
  challenge.md              Challenge requirements and deliverables
  journal.md                Chronological record of the work
docker/                     Container build files, such as single- and multi-stage Dockerfiles
docs/                       Challenge documentation, guides, and references
k8s/                        Kubernetes manifests and deployment configuration
reports/
  scans/                    Container vulnerability scan results
  sbom/                     Software bills of materials
  signatures/                Image signing and verification records (not private keys)
scripts/                     Reusable helper scripts for the challenge
sources/
  original/                 Unmodified upstream application source
  remediated/               Patched application source and dependency updates
.cache/                      Local cache; do not treat as a deliverable
.tools/                      Locally installed challenge tools; do not treat as a deliverable
.keys/                       Local signing key material; keep private and never commit or journal it
readme.md                    Workspace overview and references
```


## Work journal

- Document meaningful investigation, decisions, implementation, testing, and troubleshooting in [`assignment/journal.md`](../assignment/journal.md).
- Add concise, chronological entries as work happens. Include the date when known, what was attempted or changed, relevant commands or files, the observed result, and any follow-up.
- Record failures and incomplete work as well as successes. Do not describe a planned action as completed or claim a result that was not verified.
- Keep entries useful for the final presentation: capture the reasoning, security implications, tradeoffs, and lessons learned, not just a list of commands.
- Do not copy large command output into the journal; summarize the result and point to relevant reports or files.
- Never record credentials, tokens, private keys, or other secrets. Redact sensitive values from command examples and output.

## Challenge work

- Make changes that directly support the challenge deliverables, and preserve the user's existing work.
- Use available project tooling to validate changes. Record the validation command and its actual outcome in the journal.
- Keep security findings factual and scoped to the evidence collected; distinguish scan results from assumptions and explain tool and image versions where relevant.
- Make scripts and repeatable procedures easy to demonstrate during the technical presentation. Document each script or walkthrough in a nearby README, not the main `readme.md`, including its purpose, prerequisites, exact invocation, expected result, and relevant files or resources it changes.
- Keep presentation instructions runnable and honest: distinguish commands already tested from those not yet run, explain important flags and decision points, and note limitations or cleanup steps. Never include secrets or private key material in examples.
