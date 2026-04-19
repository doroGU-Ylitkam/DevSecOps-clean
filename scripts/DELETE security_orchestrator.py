#!/usr/bin/env python3
"""
security_orchestrator.py
========================
DevSecOps Pipeline – Bachelor Thesis Prototype

Orchestrates the post-scan phase of the security pipeline:
  1. Locates raw scanner output files in the report directory
  2. Delegates to report_merger   -> unified vulnerability list
  3. Delegates to triage_algorithm -> deduplicated + prioritised list
  4. Delegates to report_generator -> final HTML + JSON report

Usage:
    python3 security_orchestrator.py \
        --report-dir /path/to/security-reports \
        --build-id   42 \
        --app-name   thesis-app
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Local modules (same scripts/ directory)
sys.path.insert(0, str(Path(__file__).parent))
from report_merger    import ReportMerger
from triage_algorithm import TriageEngine
from report_generator import ReportGenerator

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('orchestrator')


# ─────────────────────────────────────────────────────────────────────────────
# Scanner manifest: maps logical scanner name to expected output filename
# ─────────────────────────────────────────────────────────────────────────────
SCANNER_FILES = {
    'sonarqube':  'sonarqube-issues.json',
    'owasp_dc':   'owasp-dc-report.json',
    'trivy':      'trivy-report.json',
    'owasp_zap':  'zap-report.json',
}


def locate_reports(report_dir: Path) -> dict:
    """Return {scanner_name: file_path} for all reports that exist."""
    found = {}
    for scanner, filename in SCANNER_FILES.items():
        path = report_dir / filename
        if path.exists():
            found[scanner] = path
            log.info("Found report: %s -> %s", scanner, path.name)
        else:
            log.warning("Report not found (scanner may have been skipped): %s", filename)
    return found


def save_intermediate(data: dict, path: Path, label: str) -> None:
    """Persist an intermediate result as pretty-printed JSON."""
    path.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
    count = len(data.get('vulnerabilities', []))
    log.info("Saved %s (%d vulnerabilities) -> %s", label, count, path.name)


def build_pipeline_metadata(args) -> dict:
    return {
        'build_id':   args.build_id,
        'app_name':   args.app_name,
        'timestamp':  datetime.utcnow().isoformat() + 'Z',
        'report_dir': str(args.report_dir),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main orchestration logic
# ─────────────────────────────────────────────────────────────────────────────
def run(args) -> int:
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    meta = build_pipeline_metadata(args)
    log.info("=== Security Orchestrator starting | build=%s app=%s ===",
             meta['build_id'], meta['app_name'])

    # Step 1: locate raw scanner reports
    scanner_reports = locate_reports(report_dir)
    if not scanner_reports:
        log.error("No scanner reports found in %s - nothing to process.", report_dir)
        return 1

    # Step 2: merge all reports into a unified vulnerability list
    log.info("--- Phase 1: Merging reports ---")
    merger = ReportMerger()
    merged = merger.merge(scanner_reports)
    merged['metadata'] = meta
    save_intermediate(merged, report_dir / 'merged-vulnerabilities.json', 'merged report')

    # Step 3: triage (dedup + classify + score)
    log.info("--- Phase 2: Triage (dedup + classify + score) ---")
    engine = TriageEngine()
    triaged = engine.run(merged)
    triaged['metadata'] = meta
    save_intermediate(triaged, report_dir / 'triaged-vulnerabilities.json', 'triaged report')

    # Step 4: generate final report (JSON + HTML)
    log.info("--- Phase 3: Generating final report ---")
    generator = ReportGenerator(report_dir)
    generator.generate(triaged)

    # Summary
    vulns  = triaged.get('vulnerabilities', [])
    by_sev = {}
    for v in vulns:
        sev = v.get('severity', 'UNKNOWN')
        by_sev[sev] = by_sev.get(sev, 0) + 1

    log.info("=== Pipeline complete | total=%d %s ===",
             len(vulns),
             ' '.join(f"{s}={c}" for s, c in sorted(by_sev.items())))

    # Return exit-code 2 when CRITICALs found (distinguishable from hard failure)
    return 2 if by_sev.get('CRITICAL', 0) > 0 else 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry-point
# ─────────────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description='DevSecOps Security Report Orchestrator'
    )
    parser.add_argument('--report-dir', required=True,
                        help='Directory containing raw scanner output files')
    parser.add_argument('--build-id', default='local',
                        help='Jenkins build number or identifier')
    parser.add_argument('--app-name', default='app',
                        help='Application name embedded in reports')
    return parser.parse_args()


if __name__ == '__main__':
    sys.exit(run(parse_args()))
