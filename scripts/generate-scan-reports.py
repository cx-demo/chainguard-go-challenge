#!/usr/bin/env python3
"""Generate offline Trivy comparison and govulncheck correlation HTML reports."""

from __future__ import annotations

import argparse
import html
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
COLORS = {
    "CRITICAL": "#991b1b",
    "HIGH": "#9a3412",
    "MEDIUM": "#854d0e",
    "LOW": "#1e40af",
    "UNKNOWN": "#374151",
}


def escaped(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Cannot read JSON report {path}: {error}") from error


def trivy_findings(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = read_json(path)
    if not isinstance(report, dict):
        raise SystemExit(f"Unexpected Trivy report format: {path}")
    findings: list[dict[str, Any]] = []
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for vulnerability in result.get("Vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            finding = dict(vulnerability)
            finding["Type"] = result.get("Type", "")
            finding["Target"] = result.get("Target", "")
            findings.append(finding)
    findings.sort(
        key=lambda item: (
            SEVERITY_RANK.get(str(item.get("Severity", "UNKNOWN")).upper(), 99),
            str(item.get("VulnerabilityID", "")),
            str(item.get("PkgName", "")),
        )
    )
    return report, findings


def govulncheck_report(path: Path) -> dict[str, Any]:
    """Read govulncheck's whitespace-separated JSON message stream."""
    messages: list[dict[str, Any]] = []
    try:
        content = path.read_text(encoding="utf-8")
        decoder = json.JSONDecoder()
        offset = 0
        while offset < len(content):
            while offset < len(content) and content[offset].isspace():
                offset += 1
            if offset == len(content):
                break
            try:
                message, offset = decoder.raw_decode(content, offset)
            except json.JSONDecodeError as error:
                raise SystemExit(f"Invalid govulncheck JSON at {path}: {error}") from error
            if isinstance(message, dict):
                messages.append(message)
    except OSError as error:
        raise SystemExit(f"Cannot read govulncheck report {path}: {error}") from error

    config: dict[str, Any] = {}
    osv: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    for message in messages:
        if isinstance(message.get("config"), dict):
            config.update(message["config"])
        if isinstance(message.get("osv"), dict):
            advisory = message["osv"]
            if advisory.get("id"):
                osv[advisory["id"]] = advisory
        if isinstance(message.get("finding"), dict):
            findings.append(message["finding"])
    return {"config": config, "osv": osv, "findings": findings}


def advisory_ids(advisory: dict[str, Any]) -> set[str]:
    ids = {str(advisory.get("id", "")).upper()}
    ids.update(str(alias).upper() for alias in advisory.get("aliases", []) if alias)
    ids.discard("")
    return ids


def gov_modules(finding: dict[str, Any]) -> set[str]:
    modules: set[str] = set()
    for trace in finding.get("trace") or []:
        if not isinstance(trace, dict):
            continue
        module = trace.get("module")
        if module:
            modules.add(str(module))
    return modules


def gov_versions(finding: dict[str, Any], module: str) -> set[str]:
    versions: set[str] = set()
    for trace in finding.get("trace") or []:
        if (
            isinstance(trace, dict)
            and trace.get("module") == module
            and trace.get("version")
        ):
            versions.add(str(trace["version"]).removeprefix("v"))
    return versions


def gov_has_symbol_trace(finding: dict[str, Any]) -> bool:
    return any(
        isinstance(trace, dict) and (trace.get("function") or trace.get("position"))
        for trace in finding.get("trace") or []
    )


def all_gov_advisories(*reports: dict[str, Any]) -> dict[str, dict[str, Any]]:
    advisories: dict[str, dict[str, Any]] = {}
    for report in reports:
        advisories.update(report["osv"])
    return advisories


def findings_by_advisory(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    by_id: dict[str, list[dict[str, Any]]] = {}
    for finding in report["findings"]:
        advisory_id = str(finding.get("osv", "")).upper()
        if advisory_id:
            by_id.setdefault(advisory_id, []).append(finding)
    return by_id


def version_matches(
    trivy_version: str, module: str, gov_findings: list[dict[str, Any]]
) -> bool:
    normalized = str(trivy_version or "").removeprefix("v")
    return bool(normalized) and any(
        normalized in gov_versions(item, module) for item in gov_findings
    )


def modules_match(package: str, gov_findings: list[dict[str, Any]]) -> bool:
    return bool(package) and any(package in gov_modules(item) for item in gov_findings)


def correlate(
    finding: dict[str, Any],
    advisories: dict[str, dict[str, Any]],
    source_findings: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    trivy_id = str(finding.get("VulnerabilityID", "")).upper()
    matched_advisories = [
        advisory
        for advisory in advisories.values()
        if trivy_id in advisory_ids(advisory)
    ]
    matched_ids = {
        advisory_id
        for advisory in matched_advisories
        for advisory_id in advisory_ids(advisory)
    }
    package = str(finding.get("PkgName", ""))
    source_evidence = [
        gov_finding
        for advisory_id, items in source_findings.items()
        if advisory_id in matched_ids
        for gov_finding in items
    ]
    package_evidence = [
        item for item in source_evidence if package in gov_modules(item)
    ]
    installed = str(finding.get("InstalledVersion", ""))
    symbol_evidence = [item for item in package_evidence if gov_has_symbol_trace(item)]
    version_match = version_matches(installed, package, package_evidence)
    cve_match = trivy_id.startswith("CVE-") and trivy_id in matched_ids
    evidence = {
        "Reachability": bool(symbol_evidence),
        "Package": bool(package_evidence),
        "Version": version_match,
        "CVE ID": cve_match,
    }
    evidence_count = sum(evidence.values())
    if evidence_count == 4:
        confidence = "High"
    elif evidence_count == 3:
        confidence = "Moderate"
    elif evidence_count > 0:
        confidence = "Limited"
    else:
        confidence = "Unmatched"
    reachability = (
        "Reachable source symbol path"
        if evidence["Reachability"]
        else "No reachable source symbol path reported"
    )

    matched_cves = sorted(
        advisory_id
        for advisory_id in matched_ids
        if advisory_id.startswith("CVE-")
    )

    return {
        "confidence": confidence,
        "reachability": reachability,
        "advisories": matched_advisories,
        "matched_ids": sorted(matched_ids),
        "matched_cves": matched_cves,
        "source_evidence": source_evidence,
        "package_evidence": package_evidence,
        "evidence": evidence,
        "evidence_count": evidence_count,
        "version_match": version_match,
        "module_match": bool(package_evidence),
    }


def page(title: str, body: str, generated_at: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escaped(title)}</title>
<style>
:root{{--ink:#17212b;--muted:#586575;--line:#dce2e8;--panel:#fff;--page:#f3f6f9;--blue:#245b8f}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1600px;margin:auto;padding:28px 22px 54px}}h1{{margin:0 0 6px;font-size:clamp(1.7rem,3vw,2.4rem)}}
.lede,.muted{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:18px 0}}
.card,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}}.card strong{{display:block;font-size:1.45rem}}
.card span,.meta,.muted{{color:var(--muted);font-size:.87rem}}.toolbar{{display:flex;flex-wrap:wrap;gap:10px;align-items:end;margin:16px 0}}
label{{display:grid;gap:4px;font-size:.85rem;font-weight:650}}input,select{{min-width:180px;padding:8px;border:1px solid #bbc5d0;border-radius:6px;background:#fff;font:inherit}}
button{{padding:8px 12px;border:1px solid #bbc5d0;border-radius:6px;background:#fff;color:var(--ink);font:inherit;cursor:pointer}}button:hover{{background:#eef3f8}}
.table-scroll{{overflow:auto;border:1px solid var(--line);border-radius:8px}}table{{width:100%;min-width:1200px;border-collapse:collapse;background:#fff;font-size:.84rem}}
th,td{{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid #e8edf1;max-width:340px;overflow-wrap:anywhere}}
th{{position:sticky;top:0;background:#f0f4f7;z-index:1;white-space:nowrap}}tr:last-child td{{border-bottom:0}}
.report-summaries{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr));gap:14px;margin:18px 0 28px}}
.report-summary{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:0 2px 8px #1322380a;min-width:0}}
.report-summary h2{{margin:0 0 4px;font-size:1.2rem}}.report-summary h3{{margin:14px 0 6px;font-size:.98rem}}
.summary-metrics{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin:14px 0}}
.summary-metrics>div{{border:1px solid var(--line);border-radius:8px;padding:10px}}
.summary-metrics strong{{display:block;font-size:1.3rem}}.summary-metrics span{{color:var(--muted);font-size:.8rem}}
.severity-summary{{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0}}
.summary-type-table{{overflow:auto;border:1px solid var(--line);border-radius:7px}}
.summary-type-table table{{width:100%;min-width:0;font-size:.87rem}}.summary-type-table td,.summary-type-table th{{padding:6px 9px}}
.image-details,.package-group{{background:var(--panel);border:1px solid var(--line);border-radius:9px;overflow:hidden}}
.image-details{{margin:12px 0}}.image-details>summary{{cursor:pointer;padding:15px 18px;font-size:1.05rem;font-weight:700;list-style:none}}
.image-details>summary::-webkit-details-marker,.package-group>summary::-webkit-details-marker{{display:none}}
.image-details>summary:after,.package-group>summary:after{{content:"＋";float:right;color:var(--blue)}}
.image-details[open]>summary:after,.package-group[open]>summary:after{{content:"−"}}
.image-details-body{{padding:0 16px 16px;border-top:1px solid var(--line)}}
.correlation-image,.correlation-package{{background:var(--panel);border:1px solid var(--line);border-radius:9px;overflow:hidden}}
.correlation-image{{margin:12px 0}}.correlation-image>summary{{cursor:pointer;padding:15px 18px;font-size:1.05rem;font-weight:700;list-style:none}}
.correlation-image>summary::-webkit-details-marker,.correlation-package>summary::-webkit-details-marker{{display:none}}
.correlation-image>summary:after,.correlation-package>summary:after{{content:"＋";float:right;color:var(--blue)}}
.correlation-image[open]>summary:after,.correlation-package[open]>summary:after{{content:"−"}}
.correlation-image-body{{padding:0 14px 14px;border-top:1px solid var(--line)}}
.correlation-package{{margin:9px 0}}.correlation-package>summary{{cursor:pointer;list-style:none;padding:11px 13px;background:#eaf0f5;font-weight:650}}
.correlation-package .table-scroll{{border:0;border-top:1px solid var(--line);border-radius:0}}
.correlation-package table{{min-width:1450px}}.correlation-package th{{position:static}}
.correlation-finding[hidden],.correlation-package[hidden]{{display:none}}
.report-confidence-summary{{margin:8px 0 16px;padding:12px;background:#f8fafc;border:1px solid var(--line);border-radius:8px}}
.confidence-counts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px}}
.confidence-count{{padding:8px 10px;background:#fff;border:1px solid var(--line);border-radius:7px}}
.confidence-count strong{{display:block;font-size:1.2rem}}.confidence-count span{{font-size:.82rem;color:var(--muted)}}
.source-trace{{margin-top:8px;font-size:.82rem}}
.source-trace summary{{cursor:pointer;color:var(--blue);font-weight:650}}
.trace-path{{margin-top:8px;padding:8px;background:#f8fafc;border:1px solid var(--line);border-radius:7px}}
.trace-path-title{{margin:0 0 6px;font-weight:650;color:var(--muted)}}
.trace-path ol{{list-style:none;padding:0;margin:0;display:grid;gap:5px}}
.trace-frame{{display:flex;align-items:flex-start;gap:8px;padding:6px 8px;background:white;border:1px solid var(--line);border-radius:6px}}
.trace-frame.application-frame{{border-color:#86c79b;background:#f0fdf4}}
.trace-step{{display:inline-grid;place-items:center;min-width:1.55rem;height:1.55rem;border-radius:50%;background:#e5e7eb;font-size:.74rem;font-weight:700}}
.trace-frame div{{display:grid;gap:2px;min-width:0}}.trace-frame code{{overflow-wrap:anywhere}}
.trace-location,.trace-module{{font-size:.77rem;color:var(--muted);overflow-wrap:anywhere}}
.trace-arrow{{margin-left:auto;color:var(--blue);font-weight:700}}
.high{{background:#dcfce7;color:#166534}}.moderate{{background:#fef3c7;color:#854d0e}}
.limited{{background:#fee2e2;color:#991b1b}}.metadata-only{{background:#e0e7ff;color:#3730a3}}
.unmatched{{background:#e5e7eb;color:#374151}}
.package-group{{margin:9px 0}}.package-group>summary{{cursor:pointer;list-style:none;padding:11px 13px;background:#eaf0f5;font-weight:650}}
.package-name{{overflow-wrap:anywhere}}.type-badge{{margin-left:7px;background:#e0e7ff;color:#3730a3}}
.group-count{{margin-left:8px;color:var(--muted);font-size:.84rem;font-weight:500}}
.package-group .table-scroll{{border:0;border-top:1px solid var(--line);border-radius:0}}
.package-group table{{min-width:1000px}}.package-group th{{position:static}}
.finding[hidden],.package-group[hidden]{{display:none}}
.badge{{display:inline-block;border-radius:20px;padding:2px 8px;font-weight:700;font-size:.78rem;white-space:nowrap}}
.CRITICAL{{background:#fee2e2;color:#991b1b}}.HIGH{{background:#ffedd5;color:#9a3412}}.MEDIUM{{background:#fef3c7;color:#854d0e}}.LOW{{background:#dbeafe;color:#1e40af}}.UNKNOWN{{background:#e5e7eb;color:#374151}}
.high{{background:#dcfce7;color:#166534}}.moderate{{background:#fef3c7;color:#854d0e}}.limited{{background:#fee2e2;color:#991b1b}}.metadata{{background:#e0e7ff;color:#3730a3}}.unmatched{{background:#e5e7eb;color:#374151}}
.warning{{border-left:4px solid #d97706;background:#fff7ed;padding:10px 12px}}a{{color:#245b8f}}footer{{margin-top:24px;color:var(--muted);font-size:.84rem}}
@media(max-width:600px){{main{{padding:18px 12px}}}}
</style></head><body><main>{body}
<footer>Generated {escaped(generated_at)} · Static report; no data is sent to a server.</footer></main></body></html>"""


def trivy_package_type(finding: dict[str, Any]) -> str:
    return str(finding.get("Type") or "Other")


def trivy_package_name(finding: dict[str, Any]) -> str:
    return str(finding.get("PkgName") or "Unknown package")


def trivy_database_metadata(report: dict[str, Any], artifact: str) -> dict[str, Any]:
    trivy_info = report.get("Trivy") or {}
    database = trivy_info.get("VulnerabilityDB")
    if not isinstance(database, dict) or not database.get("updatedAt"):
        raise SystemExit(
            f"Trivy vulnerability database metadata is missing for {artifact}. "
            "Re-run scripts/scan-containers.sh to capture provenance."
        )
    return database


def trivy_summary_with_report(
    label: str,
    artifact: str,
    findings: list[dict[str, Any]],
    report: dict[str, Any],
) -> str:
    severity_counts = Counter(
        str(item.get("Severity", "UNKNOWN")).upper() for item in findings
    )
    type_counts = Counter(trivy_package_type(item) for item in findings)
    fix_available = sum(bool(item.get("FixedVersion")) for item in findings)
    severity_badges = " ".join(
        f'<span class="badge {escaped(severity)}">{escaped(severity)} '
        f'{severity_counts.get(severity, 0):,}</span>'
        for severity in SEVERITIES
    )
    type_rows = "".join(
        f"<tr><th>{escaped(package_type)}</th><td>{count:,}</td></tr>"
        for package_type, count in sorted(type_counts.items())
    ) or '<tr><td colspan="2">No vulnerability findings</td></tr>'
    database = trivy_database_metadata(
        report, str(report.get("ArtifactName") or artifact)
    )
    scanner_version = (report.get("Trivy") or {}).get("Version", "Unknown")
    return f"""<section class="report-summary">
<h2>{escaped(label)}</h2><p class="meta">Artifact: {escaped(artifact)}</p>
<div class="summary-metrics"><div><strong>{len(findings):,}</strong><span>Total vulnerabilities</span></div>
<div><strong>{fix_available:,}</strong><span>Fix available</span></div>
<div><strong>{len(findings) - fix_available:,}</strong><span>No fixed version reported</span></div></div>
<p class="severity-summary">{severity_badges}</p>
<h3>Vulnerabilities by package/library type</h3>
<div class="summary-type-table"><table><tbody>{type_rows}</tbody></table></div>
<h3>Scanner database</h3>
<p class="meta">Trivy {escaped(scanner_version)} · Vulnerability DB: {escaped(database.get("source"))}
· schema version {escaped(database.get("schemaVersion"))}<br>
Last updated: {escaped(database.get("updatedAt"))}
· downloaded: {escaped(database.get("downloadedAt"))}
· next update: {escaped(database.get("nextUpdate"))}<br>
Image scan time: {escaped(report.get("CreatedAt", "not reported"))}</p>
</section>"""


def trivy_group_html(
    package_type: str, package: str, findings: list[dict[str, Any]]
) -> str:
    rows = []
    for finding in findings:
        severity = str(finding.get("Severity", "UNKNOWN")).upper()
        fixed = str(finding.get("FixedVersion") or "")
        search_text = " ".join(
            str(finding.get(key, ""))
            for key in ("VulnerabilityID", "PkgName", "Title", "Target", "InstalledVersion")
        ).lower()
        rows.append(
            f'<tr class="finding" data-search="{escaped(search_text)}" '
            f'data-severity="{escaped(severity)}" '
            f'data-fixed="{"yes" if fixed else "no"}">'
            f'<td><span class="badge {escaped(severity)}">{escaped(severity)}</span></td>'
            f'<td>{escaped(finding.get("VulnerabilityID"))}</td>'
            f'<td>{escaped(finding.get("InstalledVersion"))}</td>'
            f'<td>{escaped(fixed or "—")}</td>'
            f'<td>{escaped(finding.get("Target"))}</td>'
            f'<td>{escaped(finding.get("Title"))}</td></tr>'
        )
    fixed_count = sum(bool(item.get("FixedVersion")) for item in findings)
    return f"""<details class="package-group" data-package-type="{escaped(package_type)}">
<summary><span class="package-name">{escaped(package)}</span>
<span class="badge type-badge">{escaped(package_type)}</span>
<span class="group-count" data-total="{len(findings)}" data-fixed="{fixed_count}">{len(findings):,} vulnerabilities · {fixed_count:,} fix available</span></summary>
<div class="table-scroll"><table><thead><tr><th>Severity</th><th>Vulnerability</th>
<th>Installed</th><th>Fixed</th><th>Target</th><th>Title</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div></details>"""


def trivy_report_details(
    label: str, findings: list[dict[str, Any]]
) -> str:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        key = (trivy_package_type(finding), trivy_package_name(finding))
        groups.setdefault(key, []).append(finding)
    package_types = sorted({package_type for package_type, _ in groups})
    type_options = "".join(
        f'<option value="{escaped(package_type)}">{escaped(package_type)}</option>'
        for package_type in package_types
    )
    group_html = "".join(
        trivy_group_html(package_type, package, groups[(package_type, package)])
        for package_type, package in sorted(
            groups, key=lambda group: (group[0].lower(), group[1].lower())
        )
    )
    return f"""<details class="image-details" data-image="{escaped(label)}">
<summary>Findings for {escaped(label)} <span class="group-count">{len(findings):,} vulnerabilities</span></summary>
<div class="image-details-body">
<div class="toolbar">
<label>Search findings<input class="filter-search" type="search" placeholder="CVE, package, target, or title"></label>
<label>Severity<select class="filter-severity"><option value="">All severities</option>
{"".join(f'<option value="{s}">{s}</option>' for s in SEVERITIES)}</select></label>
<label>Package/library type<select class="filter-type"><option value="">All types</option>{type_options}</select></label>
<label>Fix status<select class="filter-fixed"><option value="">Any fix status</option>
<option value="yes">Fix available</option><option value="no">No fix reported</option></select></label>
<button type="button" class="clear-filters">Clear filters</button>
<span class="filter-count muted"></span></div>
<div class="package-groups">{group_html}</div></div></details>"""


def trivy_comparison_page(
    reports: list[tuple[str, str, dict[str, Any], list[dict[str, Any]]]],
    generated_at: str,
) -> str:
    summaries = "".join(
        trivy_summary_with_report(label, report.get("ArtifactName", artifact), findings, report)
        for label, artifact, report, findings in reports
    )
    details = "".join(
        trivy_report_details(label, findings)
        for label, _, _, findings in reports
    )
    body = f"""<h1>Trivy container scan comparison</h1>
<p class="lede">Vulnerability findings for both container images. Trivy results include OS and language-package findings; an identical CVE in two images is counted once per image.</p>
<section class="report-summaries" aria-label="Image scan summaries">{summaries}</section>
<h2>Detailed findings</h2>
<p class="muted">Expand an image report, then expand a package/library group to review its findings. Filters apply independently to each image report.</p>
<section class="image-reports" aria-label="Detailed image reports">{details}</section>
<p class="muted">Trivy report timestamps and versions are embedded in each source JSON. Findings with no fixed version are not necessarily unfixable; check the package's distribution and advisory.</p>
<script>
for(const report of document.querySelectorAll('.image-details')){{
 const search=report.querySelector('.filter-search'),severity=report.querySelector('.filter-severity');
 const type=report.querySelector('.filter-type'),fixed=report.querySelector('.filter-fixed');
 const rows=[...report.querySelectorAll('.finding')],groups=[...report.querySelectorAll('.package-group')];
 const count=report.querySelector('.filter-count');
 function filter(){{
  let visible=0;
  for(const row of rows){{
   const show=row.dataset.search.includes(search.value.toLowerCase())
    &&(!severity.value||row.dataset.severity===severity.value)
    &&(!fixed.value||row.dataset.fixed===fixed.value)
    &&(!type.value||row.closest('.package-group').dataset.packageType===type.value);
   row.hidden=!show;if(show)visible++;
  }}
  for(const group of groups){{
   const groupRows=[...group.querySelectorAll('.finding')];
   const visibleRows=groupRows.filter(row=>!row.hidden).length;
   group.hidden=visibleRows===0;
   const groupCount=group.querySelector('.group-count');
   const filtered=search.value||severity.value||fixed.value||type.value;
   groupCount.textContent=filtered
    ? `${{visibleRows.toLocaleString()}} of ${{groupRows.length.toLocaleString()}} matching findings`
    : `${{Number(groupCount.dataset.total).toLocaleString()}} vulnerabilities · ${{Number(groupCount.dataset.fixed).toLocaleString()}} fix available`;
  }}
  count.textContent=`Showing ${{visible.toLocaleString()}} of ${{rows.length.toLocaleString()}} findings`;
 }}
 [search].forEach(el=>el.addEventListener('input',filter));
 [severity,type,fixed].forEach(el=>el.addEventListener('change',filter));
 report.querySelector('.clear-filters').addEventListener('click',()=>{{
  search.value='';severity.value='';type.value='';fixed.value='';filter();
 }});
 filter();
}}
</script>"""
    return page("Trivy container scan comparison", body, generated_at)


def gov_evidence_text(evidence: list[dict[str, Any]], expected_module: str) -> str:
    parts: list[str] = []
    for finding in evidence:
        fixed = finding.get("fixed_version")
        for trace in finding.get("trace") or []:
            if isinstance(trace, dict):
                module = trace.get("module", "")
                version = trace.get("version", "")
                if module == expected_module and module:
                    parts.append(f"{module} {version}".strip())
        if fixed:
            parts.append(f"govulncheck fixed: {fixed}")
    return "; ".join(dict.fromkeys(parts)) or "—"


def gov_source_trace_html(
    evidence: list[dict[str, Any]],
    vulnerable_module: str,
    source_dir: str,
    source_link_prefix: str,
) -> str:
    traces: list[list[dict[str, Any]]] = []
    seen: set[tuple[tuple[str, str, str, int, int], ...]] = set()
    for finding in evidence:
        trace = [
            frame
            for frame in finding.get("trace") or []
            if isinstance(frame, dict)
        ]
        if not trace or not any(
            frame.get("module") == vulnerable_module
            and (frame.get("function") or frame.get("position"))
            for frame in trace
        ):
            continue
        key = tuple(
            (
                str(frame.get("module") or ""),
                str(frame.get("package") or ""),
                str(frame.get("function") or ""),
                str((frame.get("position") or {}).get("filename") or ""),
                (frame.get("position") or {}).get("line") or 0,
            )
            for frame in trace
        )
        if key in seen:
            continue
        seen.add(key)
        traces.append(trace)
    if not traces:
        return ""

    def format_frame(frame: dict[str, Any], index: int, total: int) -> str:
        module = str(frame.get("module") or "")
        package = str(frame.get("package") or "")
        function = str(frame.get("function") or "")
        position = frame.get("position") or {}
        filename = str(position.get("filename") or "")
        line = position.get("line")
        column = position.get("column")
        location = filename
        if line:
            location += f":{line}"
            if column:
                location += f":{column}"
        symbol = f"{package}.{function}" if package and function else package or function
        version = str(frame.get("version") or "")
        module_version = f"{module}@{version}" if module and version else module

        if module == "hello-server" and filename and line:
            source_path = Path(filename)
            if not source_path.is_absolute() and ".." not in source_path.parts:
                href = f"{source_link_prefix}/{source_path.as_posix()}"
                frame_location = (
                    f'<a href="{escaped(href)}#L{int(line)}">'
                    f'{escaped(source_dir)}/{escaped(location)}</a>'
                )
            else:
                frame_location = escaped(location or "Application source")
            label = "Application source"
        else:
            frame_location = escaped(location or "Location unavailable")
            label = "Vulnerable dependency" if module == vulnerable_module else "Call frame"

        arrow = "→" if index < total - 1 else "→"
        return (
            f'<li class="trace-frame {"application-frame" if module == "hello-server" else ""}">'
            f'<span class="trace-step">{index + 1}</span><div><strong>{escaped(label)}</strong> '
            f'<code>{escaped(symbol or "source symbol")}</code>'
            f'<span class="trace-location">{frame_location}</span>'
            f'<span class="trace-module">{escaped(module_version)}</span></div>'
            f'<span class="trace-arrow" aria-hidden="true">{arrow}</span></li>'
        )

    paths = []
    for path_index, trace in enumerate(traces, 1):
        forward_trace = list(reversed(trace))
        frames = "".join(
            format_frame(frame, index, len(forward_trace))
            for index, frame in enumerate(forward_trace)
        )
        paths.append(
            f'<div class="trace-path"><p class="trace-path-title">Source-to-vulnerable call path'
            f'{f" {path_index}" if len(traces) > 1 else ""}</p><ol>{frames}</ol></div>'
        )
    return (
        f'<details class="source-trace"><summary>View application source call path '
        f'({len(traces)} trace{"s" if len(traces) != 1 else ""})</summary>'
        f'<div class="trace-paths">{"".join(paths)}</div></details>'
    )


def correlation_rows(
    reports: list[tuple[str, str, dict[str, Any], list[dict[str, Any]]]],
    source_report: dict[str, Any],
    all_advisories: dict[str, dict[str, Any]],
    source_dir: str,
    source_link_prefix: str,
) -> tuple[list[dict[str, Any]], Counter[str]]:
    rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    source_by_id = findings_by_advisory(source_report)
    for label, image, _, findings in reports:
        for finding in findings:
            if str(finding.get("Type", "")).lower() not in (
                "gobinary",
                "gomod",
                "go",
                "golang",
            ):
                continue
            if str(finding.get("Target", "")) != "hello-server":
                continue
            match = correlate(finding, all_advisories, source_by_id)
            confidence = match["confidence"]
            counts[confidence] += 1
            package = str(finding.get("PkgName", ""))
            evidence_text = gov_evidence_text(match["package_evidence"], package)
            source_trace_html = gov_source_trace_html(
                match["package_evidence"],
                package,
                source_dir,
                source_link_prefix,
            )
            severity = str(finding.get("Severity", "UNKNOWN")).upper()
            search_text = " ".join(
                str(finding.get(key, ""))
                for key in (
                    "VulnerabilityID",
                    "PkgName",
                    "Title",
                    "InstalledVersion",
                    "FixedVersion",
                )
            )
            gov_versions_found = sorted(
                {
                    version
                    for evidence in match["package_evidence"]
                    for version in gov_versions(evidence, str(finding.get("PkgName", "")))
                }
            )
            rows.append(
                {
                    "image": label,
                    "severity": severity,
                    "trivy_id": str(finding.get("VulnerabilityID", "")),
                    "matched_cves": match["matched_cves"],
                    "evidence_count": match["evidence_count"],
                    "evidence_signals": match["evidence"],
                    "gov_advisory_ids": sorted(
                        advisory_id
                        for advisory_id in match["matched_ids"]
                        if advisory_id.startswith("GO-")
                    ),
                    "package": package,
                    "package_type": str(finding.get("Type") or "Other"),
                    "installed": str(finding.get("InstalledVersion", "")),
                    "fixed": str(finding.get("FixedVersion") or ""),
                    "gov_versions": gov_versions_found,
                    "confidence": confidence,
                    "reachability": match["reachability"],
                    "evidence": evidence_text,
                    "source_trace_html": source_trace_html,
                    "title": str(finding.get("Title", "")),
                    "search": (
                        search_text
                        + " "
                        + " ".join(match["matched_ids"])
                        + " "
                        + evidence_text
                        + " "
                        + source_trace_html
                    ).lower(),
                }
            )
    confidence_rank = {"High": 0, "Moderate": 1, "Limited": 2, "Unmatched": 3}
    rows.sort(
        key=lambda row: (
            confidence_rank.get(row["confidence"], 99),
            SEVERITY_RANK.get(row["severity"], 99),
            row["package"].lower(),
            row["trivy_id"],
            row["image"],
        )
    )
    return rows, counts


def correlation_row_html(item: dict[str, Any]) -> str:
    confidence = item["confidence"]
    confidence_class = confidence.lower().replace(" ", "-")
    cve_links = ", ".join(
        f'<a href="https://www.cve.org/CVERecord?id={escaped(cve)}" '
        f'target="_blank" rel="noopener noreferrer">{escaped(cve)}</a>'
        for cve in item["matched_cves"]
    ) or "—"
    gov_links = ", ".join(
        f'<a href="https://pkg.go.dev/vuln/{escaped(advisory_id)}" '
        f'target="_blank" rel="noopener noreferrer">{escaped(advisory_id)}</a>'
        for advisory_id in item["gov_advisory_ids"]
    ) or "—"
    gov_version = ", ".join(item["gov_versions"]) or "—"
    if item["evidence_signals"]["Reachability"]:
        reachability_key = "reachable"
    else:
        reachability_key = "no-symbol"
    return (
        f'<tr class="correlation-finding" data-search="{escaped(item["search"])}" '
        f'data-confidence="{escaped(confidence)}" data-severity="{escaped(item["severity"])}" '
        f'data-reachability="{reachability_key}" '
        f'data-package-type="{escaped(item["package_type"])}" '
        f'data-fixed="{"yes" if item["fixed"] else "no"}">'
        f'<td><span class="badge {escaped(confidence_class)}">{escaped(confidence)}</span>'
        f'<br><span class="muted">{item["evidence_count"]}/4 evidence matches</span></td>'
        f'<td>{escaped(item["reachability"])}{item["source_trace_html"]}</td>'
        f'<td>{cve_links}<br><span class="muted">Trivy ID: {escaped(item["trivy_id"])}'
        f'<br>govulncheck: {gov_links}</span></td>'
        f'<td>{escaped(item["package"])}</td>'
        f'<td>Trivy: {escaped(item["installed"] or "—")}<br>'
        f'govulncheck: {escaped(gov_version)}</td>'
        f'<td><span class="badge {escaped(item["severity"])}">{escaped(item["severity"])}</span></td>'
        f'<td>{escaped(item["evidence"] or "—")}</td>'
        f'<td>{escaped(item["title"])}</td></tr>'
    )


def correlation_package_groups(items: list[dict[str, Any]]) -> str:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in items:
        key = (item["package_type"], item["package"] or "Unknown package")
        groups.setdefault(key, []).append(item)

    markup = []
    for (package_type, package), findings in sorted(
        groups.items(), key=lambda entry: (entry[0][0].lower(), entry[0][1].lower())
    ):
        confidence_counts = Counter(item["confidence"] for item in findings)
        badges = " ".join(
            f'<span class="badge {escaped(name.lower().replace(" ", "-"))}">'
            f'{escaped(name)} {confidence_counts[name]}</span>'
            for name in ("High", "Moderate", "Limited", "Unmatched")
            if confidence_counts[name]
        )
        markup.append(
            f'<details class="correlation-package" data-package-type="{escaped(package_type)}">'
            f'<summary>{escaped(package)} <span class="badge type-badge">{escaped(package_type)}</span>'
            f'<span class="group-count">{len(findings):,} findings</span> {badges}</summary>'
            f'<div class="table-scroll"><table><thead><tr><th>Confidence</th>'
            f'<th>Reachability evidence</th><th>Matched CVE / Trivy ID</th>'
            f'<th>Package/library</th><th>Matched version</th>'
            f'<th>Severity</th><th>govulncheck evidence</th>'
            f'<th>Finding</th></tr></thead>'
            f'<tbody>{"".join(correlation_row_html(item) for item in findings)}</tbody>'
            f'</table></div></details>'
        )
    return "".join(markup)


def correlation_image_details(
    label: str, items: list[dict[str, Any]]
) -> str:
    group_markup = correlation_package_groups(items)
    confidence_counts = Counter(item["confidence"] for item in items)
    confidence_order = ("High", "Moderate", "Limited", "Unmatched")
    confidence_summary = "".join(
        f'<div class="confidence-count"><strong>{confidence_counts.get(confidence, 0):,}</strong>'
        f'<span>{escaped(confidence)} confidence</span></div>'
        for confidence in confidence_order
    )
    matched_cves = {
        cve for item in items for cve in item["matched_cves"]
    }
    package_names = {item["package"] for item in items if item["package"]}
    report_summary = f"""<div class="report-confidence-summary">
<div class="confidence-counts">{confidence_summary}</div>
<p class="meta">{len(items):,} application findings · {len(matched_cves):,} matched CVE IDs ·
{len(package_names):,} Go packages/libraries</p>
<p class="muted">Confidence is correlation evidence strength, not vulnerability severity. Severity remains the scanner-provided value shown in each finding.</p>
</div>"""
    package_types = sorted({item["package_type"] for item in items})
    type_options = "".join(
        f'<option value="{escaped(package_type)}">{escaped(package_type)}</option>'
        for package_type in package_types
    )
    confidence_options = "".join(
        f'<option value="{escaped(confidence)}">{escaped(confidence)}</option>'
        for confidence in ("High", "Moderate", "Limited", "Unmatched")
    )
    return f"""<details class="correlation-image" data-image="{escaped(label)}" open>
<summary>{escaped(label)} <span class="group-count">{len(items):,} findings</span>
{" ".join(f'<span class="badge {name.lower()}">{name} {confidence_counts.get(name, 0)}</span>' for name in confidence_order)}</summary>
<div class="correlation-image-body">{report_summary}<div class="toolbar">
<label>Search<input class="filter-search" type="search" placeholder="CVE, package, version, title"></label>
<label>Confidence<select class="filter-confidence"><option value="">All confidence levels</option>{confidence_options}</select></label>
<label>Severity<select class="filter-severity"><option value="">All severities</option>
{"".join(f'<option value="{s}">{s}</option>' for s in SEVERITIES)}</select></label>
<label>Package/library type<select class="filter-type"><option value="">All types</option>{type_options}</select></label>
<label>Reachability<select class="filter-reachability"><option value="">Any reachability</option>
<option value="reachable">Symbol path reported</option><option value="no-symbol">No symbol path reported</option></select></label>
<label>Fix status<select class="filter-fixed"><option value="">Any fix status</option>
<option value="yes">Fix available</option><option value="no">No fix reported</option></select></label>
<button type="button" class="clear-filters">Clear filters</button>
<span class="filter-count muted"></span></div>{group_markup}</div></details>"""


def correlation_page(
    reports: list[tuple[str, str, dict[str, Any], list[dict[str, Any]]]],
    source_report: dict[str, Any],
    generated_at: str,
    source_dir: str,
    source_link_prefix: str,
) -> str:
    advisories = all_gov_advisories(source_report)
    rows, _ = correlation_rows(
        reports, source_report, advisories, source_dir, source_link_prefix
    )
    gov_source_config = source_report["config"]
    source_db_time = gov_source_config.get("db_last_modified", "not reported")
    detail_sections = "".join(
        correlation_image_details(
            label, [item for item in rows if item["image"] == label]
        )
        for label, _, _, _ in reports
    )
    trivy_provenance_rows = []
    for label, artifact, report, _ in reports:
        database = trivy_database_metadata(
            report, str(report.get("ArtifactName") or artifact)
        )
        trivy_version = (report.get("Trivy") or {}).get("Version", "Unknown")
        trivy_provenance_rows.append(
            f'<tr><td>Trivy {escaped(trivy_version)}</td><td>{escaped(label)}'
            f'<br><span class="muted">{escaped(report.get("ArtifactName") or artifact)}</span></td>'
            f'<td>{escaped(database.get("source"))}</td>'
            f'<td>Schema {escaped(database.get("schemaVersion"))}</td>'
            f'<td>{escaped(database.get("updatedAt"))}</td>'
            f'<td>{escaped(database.get("downloadedAt"))}</td>'
            f'<td>{escaped(report.get("CreatedAt", "not reported"))}</td></tr>'
        )
    gov_version = gov_source_config.get("scanner_version", "version not reported")
    gov_database = gov_source_config.get("db", "database not reported")
    gov_scan = (
        f'{gov_source_config.get("scan_mode", "mode not reported")} / '
        f'{gov_source_config.get("scan_level", "level not reported")}'
    )
    body = f"""    <h1>govulncheck ↔ Trivy correlation</h1>
    <p class="lede">Go package findings from each Trivy image report are matched against one govulncheck source scan of the shared application source. Confidence describes evidence strength, not exploitability.</p>
    <p class="warning">The correlation includes only Trivy findings for the application binary (<code>hello-server</code>). Other Go binaries in the single-stage image, including compiler/toolchain files, remain visible in the Trivy comparison but are not source-correlated.</p>
    <h2>Scanner vulnerability databases</h2>
<p class="muted">Database provenance is captured with each scan. “Last updated” is the database's published update timestamp; “downloaded” is when Trivy's local cache retrieved it. Govulncheck reports the database's last-modified timestamp.</p>
<div class="table-scroll"><table><thead><tr><th>Scanner/version</th><th>Image/artifact</th>
<th>Database source</th><th>Database version</th><th>Last updated</th><th>Downloaded</th><th>Scan time</th></tr></thead>
<tbody>{''.join(trivy_provenance_rows)}
<tr><td>govulncheck {escaped(gov_version)}<br><span class="muted">Go {escaped(gov_source_config.get("go_version", "not reported"))}; {escaped(gov_scan)}</span></td>
<td>Source: <code>{escaped(source_dir)}</code></td><td>{escaped(gov_database)}</td>
<td>Advisory database stream</td><td>{escaped(source_db_time)}</td><td>Not reported</td>
<td>Not recorded in govulncheck JSON</td></tr></tbody></table></div>
<p class="muted">govulncheck JSON does not include a scan timestamp. Source reachability describes <code>{escaped(source_dir)}</code>, not proof of exploitability in a specific image.</p>
<h2>Correlation by Trivy report</h2>
<p class="muted">Each report shows its confidence summary immediately above its findings. Collapse an image report if needed, or expand a package/library group for details; filters apply independently within each image report. Confidence is correlation evidence strength, not severity.</p>
<section class="correlation-reports" aria-label="Correlation by Trivy report">{detail_sections}</section>
<h2>Confidence definition</h2><section class="panel"><p>Confidence is not a vulnerability severity rating. It measures how many of four independent correlation signals agree between govulncheck and Trivy for a finding:</p>
<ul><li><strong>Reachability:</strong> govulncheck reports a reachable source symbol path.</li>
<li><strong>Package:</strong> the exact Go package/module name matches.</li>
<li><strong>Version:</strong> the installed Trivy package version matches govulncheck's version for that same module.</li>
<li><strong>CVE ID:</strong> the Trivy CVE identifier is present as the exact CVE ID in the govulncheck advisory or its aliases.</li></ul>
<p><strong>High</strong> means 4/4 signals match. <strong>Moderate</strong> means 3/4. <strong>Limited</strong> means 1-2/4. <strong>Unmatched</strong> means 0/4. Trivy severity is an independent scanner assessment, not an input to confidence. A low-confidence result is not proof of safety, and high confidence is not proof of exploitability.</p>
<p>Trivy OS-package rows are excluded from Go correlation. Matching uses advisory IDs and published aliases; it does not infer matches from similar-looking CVE numbers or titles. Different scanner databases, image build toolchains, and advisory data can affect results.</p></section>
<footer>Govulncheck JSON is a stream of JSON messages. Documentation: <a href="https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck">govulncheck</a> · <a href="https://trivy.dev/latest/docs/scanner/vulnerability/">Trivy</a>.</footer>
<script>
for(const report of document.querySelectorAll('.correlation-image')){{
 const search=report.querySelector('.filter-search');
 const confidence=report.querySelector('.filter-confidence');
 const severity=report.querySelector('.filter-severity');
 const type=report.querySelector('.filter-type');
 const reachability=report.querySelector('.filter-reachability');
 const fixed=report.querySelector('.filter-fixed');
 const rows=[...report.querySelectorAll('.correlation-finding')];
 const groups=[...report.querySelectorAll('.correlation-package')];
 const count=report.querySelector('.filter-count');
 function filter(){{
  let visible=0;
  for(const row of rows){{
   const show=row.dataset.search.includes(search.value.toLowerCase())
    &&(!confidence.value||row.dataset.confidence===confidence.value)
    &&(!severity.value||row.dataset.severity===severity.value)
    &&(!type.value||row.dataset.packageType===type.value)
    &&(!reachability.value||row.dataset.reachability===reachability.value)
    &&(!fixed.value||row.dataset.fixed===fixed.value);
   row.hidden=!show;if(show)visible++;
  }}
  for(const group of groups){{
   const groupRows=[...group.querySelectorAll('.correlation-finding')];
   const visibleRows=groupRows.filter(row=>!row.hidden).length;
   group.hidden=visibleRows===0;
   group.querySelector('.group-count').textContent=`${{visibleRows.toLocaleString()}} of ${{groupRows.length.toLocaleString()}} findings`;
  }}
  count.textContent=`Showing ${{visible.toLocaleString()}} of ${{rows.length.toLocaleString()}} findings`;
 }}
 search.addEventListener('input',filter);
 [confidence,severity,type,reachability,fixed].forEach(el=>el.addEventListener('change',filter));
 report.querySelector('.clear-filters').addEventListener('click',()=>{{
  search.value='';confidence.value='';severity.value='';type.value='';reachability.value='';fixed.value='';filter();
 }});
 filter();
}}
</script>"""
    return page("govulncheck and Trivy correlation", body, generated_at)


def parse_trivy_report(value: str) -> tuple[str, Path]:
    label, separator, path = value.partition("=")
    if not separator or not label.strip() or not path.strip():
        raise argparse.ArgumentTypeError(
            "expected LABEL=PATH, for example 'Single-stage=reports/single.trivy.json'"
        )
    return label.strip(), Path(path.strip())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trivy-report",
        action="append",
        type=parse_trivy_report,
        metavar="LABEL=PATH",
        required=True,
        help="Trivy JSON report and display label; may be supplied more than once",
    )
    parser.add_argument(
        "--govulncheck-report",
        type=Path,
        required=True,
        metavar="PATH",
        help="govulncheck JSON message-stream report",
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path("sources/original"),
        metavar="PATH",
        help="source directory scanned by govulncheck, relative to the repository root",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="directory for generated HTML (defaults to the first Trivy report's directory)",
    )
    parser.add_argument(
        "--comparison-output",
        type=Path,
        metavar="PATH",
        help="comparison HTML output path (default: OUTPUT_DIR/trivy-comparison.html)",
    )
    parser.add_argument(
        "--correlation-output",
        type=Path,
        metavar="PATH",
        help="correlation HTML output path (default: OUTPUT_DIR/govulncheck-trivy-correlation.html)",
    )
    args = parser.parse_args()

    labels = [label for label, _ in args.trivy_report]
    if len(labels) != len(set(labels)):
        parser.error("each --trivy-report must have a unique label")

    reports = []
    for label, input_path in args.trivy_report:
        trivy_path = input_path.resolve()
        if not trivy_path.is_file():
            raise SystemExit(f"Required report is missing: {trivy_path}")
        report, findings = trivy_findings(trivy_path)
        artifact = str(report.get("ArtifactName") or report.get("ArtifactInfo", {}).get("ID") or "")
        reports.append((label, artifact, report, findings))

    source_path = args.govulncheck_report.resolve()
    if not source_path.is_file():
        raise SystemExit(f"Required report is missing: {source_path}")
    if args.source_dir.is_absolute() or ".." in args.source_dir.parts:
        parser.error("--source-dir must be a repository-relative path without '..'")
    source_dir_path = args.source_dir.resolve()
    if not source_dir_path.is_dir():
        raise SystemExit(f"Source directory is missing: {source_dir_path}")
    source_dir = args.source_dir.as_posix().rstrip("/")
    source_report = govulncheck_report(source_path)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    output_dir = (args.output_dir or args.trivy_report[0][1].parent).resolve()
    comparison_path = (
        args.comparison_output or output_dir / "trivy-comparison.html"
    ).resolve()
    correlation_path = (
        args.correlation_output or output_dir / "govulncheck-trivy-correlation.html"
    ).resolve()
    if comparison_path == correlation_path:
        parser.error("--comparison-output and --correlation-output must be different paths")
    comparison_path.parent.mkdir(parents=True, exist_ok=True)
    correlation_path.parent.mkdir(parents=True, exist_ok=True)
    source_link_prefix = Path(
        os.path.relpath(source_dir_path, start=correlation_path.parent)
    ).as_posix()
    comparison_path.write_text(trivy_comparison_page(reports, generated_at), encoding="utf-8")
    correlation_path.write_text(
        correlation_page(
            reports,
            source_report,
            generated_at,
            source_dir,
            source_link_prefix,
        ),
        encoding="utf-8",
    )
    print(f"Wrote {comparison_path}")
    print(f"Wrote {correlation_path}")


if __name__ == "__main__":
    main()
