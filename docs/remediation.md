# Go vulnerability triage and remediation

## Scope and baseline

`sources/original` is kept as the unmodified baseline. `sources/remediated` is a copy of that module with only its Go/toolchain and dependency versions changed. This makes the original scan reproducible and allows the two source trees to be compared independently.

The original finding set is in `reports/scans/original/source.govulncheck.json`. Its metadata says the scan used Go 1.27.4 and a vulnerability database last modified on 2026-11-11. That database timestamp is later than the session date of 2026-11-09, so treat findings and fix floors derived from this snapshot as provisional. Re-run govulncheck with a current database before using the results as a release or production sign-off.

## Triage method

1. Check the report's `config` record for scanner version, Go version, source/binary mode, scan level, and database timestamp. Check the `SBOM` record to identify the versions actually scanned.
2. For each finding, use its OSV ID, affected module/package, affected version range, fixed version, vulnerable symbols, and trace together. A dependency appearing in the module graph is not proof that the vulnerable behavior is reachable or exploitable.
3. Distinguish application-reachable findings from module-only matches and review the application call path. This service registers only a static `GET /` handler; it does not configure a custom TLS or h2c server. The HTTP/2 denial-of-service matches therefore did not establish that this configuration exposes the affected HTTP/2 server paths.
4. Choose the lowest fixed version that resolves all applicable findings for a module. Then account for minimum versions required by the selected dependency graph; Go's minimal version selection may require a higher compatible version. Do not use `@latest` as a substitute for checking advisory fix versions.
5. Apply changes only in `sources/remediated`, preserve the original source, refresh `go.sum` with Go tooling, and repeat the same source scan against the remediated module.

## Applied version floors

The following versions are the minimum floors selected from the supplied report, with transitive minimums respected. Go standard-library findings are fixed by upgrading the Go toolchain.

| Component | Original | Remediated | Triage note |
|---|---|---|---|
| Go language/toolchain | `go 1.18` | `go 1.27`, `toolchain go1.27.4` | The report's standard-library fix floor is Go 1.27.4. |
| `github.com/gin-gonic/gin` | `v1.8.1` | `v1.9.1` | Clears the report's Gin advisory floor. |
| `golang.org/x/crypto` | `v0.0.0-20210711020723-a769d52b0f97` | `v0.58.1-0.20261009181718-2f1f834330b2` | The report's highest listed fixed version; not upgraded to a later tag. |
| `golang.org/x/net` | `v0.0.0-20210226172049-e18ecbb05110` | `v0.62.0` | Clears the highest listed x/net fix floor. |
| `golang.org/x/sys` | `v0.0.0-20210806184541-e5e7981a1069` | `v0.49.0` | Higher than the report's x/sys fix floor because the selected x/crypto and x/net versions require it. |
| `golang.org/x/text` | `v0.3.6` | `v0.43.0` | Higher than the report's x/text fix floor because the selected x/crypto and x/net versions require it. |
| `google.golang.org/protobuf` | `v1.28.0` | `v1.33.0` | Matches the report's fix floor. |

These are security-maintenance changes, not proof that each affected symbol is used by this application. The original source scan reported some findings for APIs not called by this service; module updates are kept in the remediated copy to clear the reported dependency floors.

## Re-scan and verify

Run the checks from the repository root with Go 1.27.4 and govulncheck installed:

```sh
cd sources/remediated
go mod tidy
go mod verify
go test ./...
cd ../..
govulncheck -json -C "$PWD/sources/remediated" ./... \
  > reports/scans/remediated/source.govulncheck.json
```

Compare the remediated report's `config` and `SBOM` records to the original report, then review any remaining findings individually. A clean scan does not itself prove that the built container is free of vulnerabilities; scan the built image separately with Trivy.
