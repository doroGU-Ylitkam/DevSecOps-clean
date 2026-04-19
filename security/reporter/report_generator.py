#!/usr/bin/env python3
"""
report_generator.py  –  генератор финального отчета
=============================================================
Генерирует публикуемый рапорт об обнаруженных уязвимостях в форматах JSON и HTML
из triaged-vulnerabilities.json , разработанный vulnerability_triage.py.

Применение
-----
  python3 report_generator.py \\
      --input   reports/triaged-vulnerabilities.json \\
      --output  reports/final-vulnerability-report.html \\
      --json    reports/final-vulnerability-report.json \\
      --build   42 \\
      --app     spring-boot-app \\
      --version 1.0
"""

import argparse, json, logging
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("reporter")


# ── Определение цветов для каждой уязвимости  ──────────────────────────────────────────
SEV_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#16a34a",
    "INFO":     "#6b7280",
}

PRIO_COLORS = {
    "IMMEDIATE": "#dc2626",
    "HIGH":      "#ea580c",
    "MEDIUM":    "#d97706",
    "LOW":       "#16a34a",
}

PRIO_BADGES = {
    "IMMEDIATE": "🔴 IMMEDIATE",
    "HIGH":      "🟠 HIGH",
    "MEDIUM":    "🟡 MEDIUM",
    "LOW":       "🟢 LOW",
}


# ── Шаблон HTML ─────────────────────────────────────────────────────────────

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Vulnerability Report – {app_name}</title>
<style>
  :root {{
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #16a34a;      --info: #6b7280;
    --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0;
    --text: #1e293b; --muted: #64748b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: system-ui, -apple-system, sans-serif;
          background: var(--bg); color: var(--text); font-size: 14px; }}
  header {{ background: #1e293b; color: #fff; padding: 24px 32px; }}
  header h1 {{ font-size: 22px; font-weight: 700; }}
  header p {{ color: #94a3b8; margin-top: 4px; font-size: 13px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px 32px; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: var(--card); border: 1px solid var(--border);
           border-radius: 8px; padding: 20px; }}
  .card h3 {{ font-size: 12px; font-weight: 600; text-transform: uppercase;
              letter-spacing: .05em; color: var(--muted); margin-bottom: 8px; }}
  .card .big {{ font-size: 36px; font-weight: 700; }}
  .card .sub {{ font-size: 12px; color: var(--muted); margin-top: 4px; }}
  .section-title {{ font-size: 16px; font-weight: 700; margin: 24px 0 12px; }}
  .bar-chart {{ background: var(--card); border: 1px solid var(--border);
                border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
  .bar-row {{ display: flex; align-items: center; margin-bottom: 10px; }}
  .bar-label {{ width: 100px; font-size: 12px; font-weight: 600; }}
  .bar-wrap {{ flex: 1; background: #f1f5f9; border-radius: 4px; height: 20px;
               overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 4px; transition: width .5s; }}
  .bar-count {{ width: 40px; text-align: right; font-size: 12px; color: var(--muted); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card);
           border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ background: #f1f5f9; font-size: 11px; font-weight: 700; text-transform: uppercase;
        letter-spacing: .05em; padding: 10px 14px; text-align: left;
        border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 14px; border-bottom: 1px solid var(--border);
        vertical-align: top; font-size: 13px; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ background: #f8fafc; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 9999px;
            font-size: 11px; font-weight: 700; color: #fff; }}
  .tool-tag {{ display: inline-block; padding: 2px 7px; border-radius: 4px;
               font-size: 11px; background: #e2e8f0; color: #475569; }}
  .cve {{ font-family: monospace; font-size: 12px; color: #3b82f6; }}
  .score {{ font-family: monospace; font-weight: 700; }}
  details {{ margin-top: 4px; }}
  summary {{ cursor: pointer; color: #3b82f6; font-size: 12px; }}
  .fix-box {{ background: #f0fdf4; border-left: 3px solid #16a34a;
              padding: 8px 12px; margin-top: 6px; font-size: 12px;
              border-radius: 0 4px 4px 0; }}
  footer {{ text-align: center; color: var(--muted); font-size: 12px;
            padding: 24px; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<header>
  <h1>🛡️ Security Vulnerability Report</h1>
  <p>Application: <strong>{app_name}</strong> &nbsp;|&nbsp;
     Build: <strong>#{build_number}</strong> &nbsp;|&nbsp;
     Version: <strong>{version}</strong> &nbsp;|&nbsp;
     Generated: <strong>{generated_at}</strong></p>
</header>
<div class="container">

  <!-- ── Summary cards ── -->
  <div class="grid-4">
    <div class="card">
      <h3>Total Findings</h3>
      <div class="big">{total}</div>
      <div class="sub">{unique} unique after dedup</div>
    </div>
    <div class="card" style="border-top:3px solid var(--critical)">
      <h3>Critical / High</h3>
      <div class="big" style="color:var(--critical)">{crit_high}</div>
      <div class="sub">Immediate / High priority</div>
    </div>
    <div class="card" style="border-top:3px solid var(--medium)">
      <h3>Medium</h3>
      <div class="big" style="color:var(--medium)">{medium_count}</div>
      <div class="sub">Plan for next release</div>
    </div>
    <div class="card" style="border-top:3px solid var(--low)">
      <h3>Low / Info</h3>
      <div class="big" style="color:var(--low)">{low_info}</div>
      <div class="sub">Track in backlog</div>
    </div>
  </div>

  <!-- ── Severity bar chart ── -->
  <div class="bar-chart">
    <div class="section-title" style="margin-top:0">Severity Distribution</div>
{severity_bars}
  </div>

  <!-- ── Tool coverage ── -->
  <div class="bar-chart">
    <div class="section-title" style="margin-top:0">Findings by Scanner</div>
{tool_bars}
  </div>

  <!-- ── Vulnerability table ── -->
  <div class="section-title">Prioritised Vulnerability List</div>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Priority</th>
        <th>Score</th>
        <th>Severity</th>
        <th>CVE</th>
        <th>Title / Component</th>
        <th>Scanner</th>
        <th>Fix</th>
      </tr>
    </thead>
    <tbody>
{table_rows}
    </tbody>
  </table>

</div>
<footer>
  DevSecOps Prototype &nbsp;|&nbsp; Bachelor Thesis &nbsp;|&nbsp;
  Generated by report_generator.py &nbsp;|&nbsp; {generated_at}
</footer>
</body>
</html>
"""


# ── Обработка помощников (комментариев к уязвимостям) ──────────────────────────────────────────────────────────

def sev_badge(sev: str) -> str:
    color = SEV_COLORS.get(sev.upper(), "#6b7280")
    return f'<span class="badge" style="background:{color}">{sev}</span>'


def prio_badge(prio: str) -> str:
    color = PRIO_COLORS.get(prio, "#6b7280")
    label = PRIO_BADGES.get(prio, prio)
    return f'<span class="badge" style="background:{color}">{label}</span>'


def bar_html(label: str, count: int, max_count: int, color: str) -> str:
    pct = (count / max_count * 100) if max_count else 0
    return (
        f'    <div class="bar-row">'
        f'<div class="bar-label">{label}</div>'
        f'<div class="bar-wrap"><div class="bar-fill" '
        f'style="width:{pct:.1f}%;background:{color}"></div></div>'
        f'<div class="bar-count">{count}</div>'
        f'</div>\n'
    )


def build_table_rows(vulns: list) -> str:
    rows = []
    for i, v in enumerate(vulns, 1):
        t = v.get("triage", {})
        sev       = v.get("severity", "MEDIUM")
        prio      = t.get("priority_label", "LOW")
        score     = t.get("priority_score", 0.0)
        cve       = v.get("cve", "")
        title     = v.get("title", "")[:80]
        component = v.get("component", "")[:60]
        tool      = v.get("source_tool", "")
        fix       = v.get("fix_recommendation", "")[:200]

        cve_html = (f'<span class="cve">{cve}</span>' if cve else
                    '<span style="color:#94a3b8">—</span>')

        reported  = ", ".join(v.get("reported_by", [tool]))
        tools_html = "".join(f'<span class="tool-tag">{t}</span> ' for t in reported.split(", "))

        fix_html = ""
        if fix:
            fix_html = (f'<details><summary>View fix</summary>'
                        f'<div class="fix-box">{fix}</div></details>')

        rows.append(
            f"      <tr>\n"
            f"        <td>{i}</td>\n"
            f"        <td>{prio_badge(prio)}</td>\n"
            f"        <td><span class='score'>{score:.1f}</span></td>\n"
            f"        <td>{sev_badge(sev)}</td>\n"
            f"        <td>{cve_html}</td>\n"
            f"        <td><strong>{title}</strong>"
            f"{'<br><small style=color:#64748b>' + component + '</small>' if component else ''}</td>\n"
            f"        <td>{tools_html}</td>\n"
            f"        <td>{fix_html}</td>\n"
            f"      </tr>"
        )
    return "\n".join(rows)


# ── Основной модуль генерации рапорта ────────────────────────────────────────────────────

def generate(input_path, html_out, json_out, build_number, app_name, version):
    data = json.loads(Path(input_path).read_text())
    vulns = data.get("vulnerabilities", [])
    summary = data.get("summary", {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Подсчет уязвимостей
    sev_counts = summary.get("by_severity", {})
    by_prio    = summary.get("by_priority", {})

    total      = summary.get("total", len(vulns))
    crit_high  = sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0)
    medium_cnt = sev_counts.get("MEDIUM", 0)
    low_info   = sev_counts.get("LOW", 0) + sev_counts.get("INFO", 0)

    # Индикатор серьезности уязвимостей
    max_sev = max(sev_counts.values(), default=1)
    sev_bars = ""
    for sev, color in SEV_COLORS.items():
        cnt = sev_counts.get(sev, 0)
        sev_bars += bar_html(sev, cnt, max_sev, color)

    # Панель инструментов
    tool_counts: dict = {}
    for v in vulns:
        for t in v.get("reported_by", [v.get("source_tool","unknown")]):
            tool_counts[t] = tool_counts.get(t, 0) + 1
    max_tool = max(tool_counts.values(), default=1)
    tool_bars = ""
    tool_colors = ["#3b82f6","#8b5cf6","#06b6d4","#10b981","#f59e0b"]
    for idx, (tool, cnt) in enumerate(sorted(tool_counts.items(), key=lambda x: -x[1])):
        tool_bars += bar_html(tool, cnt, max_tool, tool_colors[idx % len(tool_colors)])

    html = HTML_TEMPLATE.format(
        app_name       = app_name,
        build_number   = build_number,
        version        = version,
        generated_at   = now,
        total          = total,
        unique         = total,
        crit_high      = crit_high,
        medium_count   = medium_cnt,
        low_info       = low_info,
        severity_bars  = sev_bars,
        tool_bars      = tool_bars,
        table_rows     = build_table_rows(vulns),
    )

    Path(html_out).parent.mkdir(parents=True, exist_ok=True)
    Path(html_out).write_text(html)
    log.info("HTML report written to %s", html_out)

    if json_out:
        final_json = {
            "schema_version": "1.0",
            "report_type": "final",
            "app_name": app_name,
            "build_number": build_number,
            "version": version,
            "generated_at": now,
            "summary": {
                "total": total,
                "by_severity": sev_counts,
                "by_priority": by_prio,
            },
            "vulnerabilities": vulns,
        }
        Path(json_out).write_text(json.dumps(final_json, indent=2))
        log.info("JSON report written to %s", json_out)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="DevSecOps Final Report Generator")
    p.add_argument("--input",   required=True)
    p.add_argument("--output",  required=True,  help="HTML output path")
    p.add_argument("--json",    default=None,   help="JSON output path (optional)")
    p.add_argument("--build",   default="N/A")
    p.add_argument("--app",     default="Application")
    p.add_argument("--version", default="1.0")
    args = p.parse_args()
    generate(args.input, args.output, args.json, args.build, args.app, args.version)


if __name__ == "__main__":
    main()
