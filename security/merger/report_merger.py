#!/usr/bin/env python3
"""
report_merger.py  –  файл слияния отчетов
==========================================================
Производит слияние нормализованных отчетов с множества сканнеров в
один отчет (в JSON-формате).

Этапы
-----
1. Загрузка каждого нормализованного JSON отчета, сформированного security_orchestrator.py
2. Сборка всех обнаруженных уязвимостей в один список
3. Обнаружение и удаление дубликатов (одинаковые уязвимости или идентичные кмментарии + обнаруженный элемент)
4. Создание единого отчета с метаданными подтверждающими достоверность собранной информации (дата запуска, номер сборки и др.)

применение
-----
  python3 report_merger.py \\
      --inputs reports/sonarqube-report.json \\
               reports/dependency-check-normalized.json \\
               reports/trivy-normalized.json \\
               reports/zap-report.json \\
      --output reports/merged-vulnerabilities.json
"""

import argparse, hashlib, json, logging
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("merger")


# ── Deduplication helpers ─────────────────────────────────────────────────────

def _dedup_key(v: dict) -> str:
    """
    Build a canonical key for deduplication.
    Priority:
      1. CVE ID   – exact same CVE reported by multiple scanners
      2. title + component normalised – same library issue, no CVE
      3. title + file_path + line     – same code-level finding
    """
    cve = v.get("cve", "").strip().upper()
    if cve and cve.startswith("CVE-"):
        return f"CVE:{cve}"

    title_norm = v.get("title", "").lower().strip()
    component  = v.get("component", "").lower().strip()
    file_path  = v.get("file_path", "").lower().strip()
    line       = str(v.get("line", ""))

    if component:
        raw = f"TITLE:{title_norm}|COMP:{component}"
    else:
        raw = f"TITLE:{title_norm}|FILE:{file_path}|LINE:{line}"

    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def deduplicate(vulnerabilities: list) -> list:
    """
    Remove duplicates, keeping the entry with the highest CVSS score
    and recording which tools also reported it.
    """
    seen: dict = {}          # key -> best vulnerability dict
    sources: dict = {}       # key -> set of source tool names

    for v in vulnerabilities:
        key = _dedup_key(v)
        sources.setdefault(key, set()).add(v.get("source_tool", "unknown"))

        if key not in seen:
            seen[key] = v
        else:
            # Keep the entry with the higher CVSS score for richer data
            if v.get("cvss_score", 0) > seen[key].get("cvss_score", 0):
                # Preserve original source list before overwrite
                original_tools = sources[key]
                seen[key] = v
                sources[key] = original_tools

    # Annotate each kept entry with the full source-tool list
    result = []
    for key, v in seen.items():
        v = dict(v)  # shallow copy to avoid mutating input
        v["reported_by"] = sorted(sources[key])
        v["is_duplicate"] = len(sources[key]) > 1
        result.append(v)

    return result


# ── Severity counter ──────────────────────────────────────────────────────────

def count_by_severity(vulnerabilities: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulnerabilities:
        sev = v.get("severity", "MEDIUM").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ── Main merge logic ──────────────────────────────────────────────────────────

def merge(input_paths: list, output_path: str):
    all_vulns = []
    tool_summaries = {}

    for path_str in input_paths:
        path = Path(path_str)
        if not path.exists():
            log.warning("Input file not found, skipping: %s", path)
            continue

        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            log.warning("Failed to parse %s: %s", path, e)
            continue

        tool = data.get("tool", path.stem)
        raw_vulns = data.get("vulnerabilities", [])
        tool_summaries[tool] = {
            "source_file": str(path),
            "raw_count": len(raw_vulns),
        }
        log.info("Loaded %d vulnerabilities from %s (%s)", len(raw_vulns), path.name, tool)
        all_vulns.extend(raw_vulns)

    log.info("Total raw vulnerabilities before dedup: %d", len(all_vulns))
    deduped = deduplicate(all_vulns)
    log.info("Vulnerabilities after deduplication: %d (removed %d duplicates)",
             len(deduped), len(all_vulns) - len(deduped))

    severity_summary = count_by_severity(deduped)

    report = {
        "schema_version": "1.0",
        "report_type": "merged",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_raw": len(all_vulns),
            "total_unique": len(deduped),
            "duplicates_removed": len(all_vulns) - len(deduped),
            "by_severity": severity_summary,
            "by_tool": tool_summaries,
        },
        "vulnerabilities": deduped,
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(report, indent=2))
    log.info("Merged report written to %s", output_path)

    # Print a summary table to stdout
    print("\n" + "="*55)
    print("  MERGE SUMMARY")
    print("="*55)
    print(f"  Raw findings    : {len(all_vulns)}")
    print(f"  Unique findings : {len(deduped)}")
    print(f"  Deduplicates    : {len(all_vulns) - len(deduped)}")
    print("-"*55)
    for sev, cnt in severity_summary.items():
        print(f"  {sev:<12}: {cnt}")
    print("="*55 + "\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="DevSecOps Report Merger")
    p.add_argument("--inputs", nargs="+", required=True,
                   help="Normalised JSON reports from security_orchestrator.py")
    p.add_argument("--output", required=True,
                   help="Output path for the unified merged report")
    args = p.parse_args()
    merge(args.inputs, args.output)


if __name__ == "__main__":
    main()
