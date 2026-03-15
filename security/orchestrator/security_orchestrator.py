#!/usr/bin/env python3
"""
security_orchestrator.py  –  DevSecOps Prototype (Bachelor Thesis)
===================================================================
Orchestrates security scanners (SonarQube, OWASP Dependency-Check,
Trivy, OWASP ZAP) and normalises their output into a unified JSON schema.
"""

import argparse, base64, json, logging, sys, time, urllib.request, urllib.parse
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("orchestrator")

# ── Unified vulnerability schema ──────────────────────────────────────────────
SEVERITY_NORM = {
    "critical":"CRITICAL","high":"HIGH","blocker":"HIGH",
    "major":"MEDIUM","medium":"MEDIUM","moderate":"MEDIUM",
    "low":"LOW","minor":"LOW","info":"INFO","informational":"INFO","note":"INFO",
}

def norm_sev(raw: str) -> str:
    return SEVERITY_NORM.get(str(raw).lower(), "MEDIUM")

def vuln(vid, title, desc, sev, cvss, tool, cve="",
         component="", file_path="", line=0, fix="", refs=None):
    return {
        "id": vid, "title": title, "description": desc,
        "severity": norm_sev(sev), "cvss_score": float(cvss), "cve": cve,
        "component": component, "file_path": file_path, "line": line,
        "fix_recommendation": fix, "references": refs or [],
        "source_tool": tool,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }

# ── HTTP helpers ──────────────────────────────────────────────────────────────
def http_get(url, token=None, retries=3):
    req = urllib.request.Request(url)
    if token:
        cred = base64.b64encode(f"{token}:".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
    req.add_header("Accept", "application/json")
    for i in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            log.warning("Attempt %d/%d failed: %s", i, retries, e)
            if i < retries:
                time.sleep(3)
    raise RuntimeError(f"Failed to GET {url}")

# ── SonarQube ─────────────────────────────────────────────────────────────────
class SonarQubeAdapter:
    SEV_CVSS = {"BLOCKER":9.0,"CRITICAL":8.0,"MAJOR":6.0,"MINOR":3.0,"INFO":1.0}

    def __init__(self, host, token, project):
        self.host, self.token, self.project = host.rstrip("/"), token, project

    def collect(self):
        return self._fetch_issues() + self._fetch_hotspots()

    def _fetch_issues(self):
        results, page, page_size, total = [], 1, 100, None
        while True:
            url = (f"{self.host}/api/issues/search"
                   f"?componentKeys={self.project}&types=VULNERABILITY&ps={page_size}&p={page}")
            data = http_get(url, self.token)
            if total is None: total = data.get("total", 0)
            for issue in data.get("issues", []):
                sev = issue.get("severity", "MAJOR")
                results.append(vuln(
                    vid=issue.get("key", f"SONAR-{len(results)}"),
                    title=issue.get("message", "SonarQube Issue"),
                    desc=issue.get("message", ""), sev=sev,
                    cvss=self.SEV_CVSS.get(sev, 5.0), tool="sonarqube",
                    component=issue.get("component",""),
                    file_path=issue.get("component","").split(":")[-1],
                    line=issue.get("line", 0),
                    fix="Review and remediate as per SonarQube guidance.",
                ))
            if page * page_size >= total: break
            page += 1
        log.info("SonarQube: %d issues", len(results))
        return results

    def _fetch_hotspots(self):
        results = []
        try:
            url = f"{self.host}/api/hotspots/search?projectKey={self.project}&ps=500"
            data = http_get(url, self.token)
            for hs in data.get("hotspots", []):
                results.append(vuln(
                    vid=hs.get("key", f"SONAR-HS-{len(results)}"),
                    title=hs.get("message", "Security Hotspot"),
                    desc=hs.get("message", ""), sev=hs.get("vulnerabilityProbability","MEDIUM"),
                    cvss=5.0, tool="sonarqube",
                    component=hs.get("component",""),
                    file_path=hs.get("component","").split(":")[-1],
                    line=hs.get("line", 0),
                    fix="Review this security hotspot to determine whether it represents a real vulnerability.",
                ))
        except Exception as e:
            log.warning("Could not fetch SonarQube hotspots: %s", e)
        log.info("SonarQube: %d hotspots", len(results))
        return results

# ── Dependency-Check ─────────────────────────────────────────────────────────
class DependencyCheckAdapter:
    def __init__(self, path): self.path = Path(path)

    def collect(self):
        raw = json.loads(self.path.read_text())
        results = []
        for dep in raw.get("dependencies", []):
            for v in dep.get("vulnerabilities", []):
                cve = v.get("name", "")
                cvss = self._cvss(v)
                results.append(vuln(
                    vid=cve or f"DC-{len(results)}",
                    title=v.get("name", "Dependency Vulnerability"),
                    desc=v.get("description", ""), sev=v.get("severity","MEDIUM"),
                    cvss=cvss, tool="dependency-check", cve=cve,
                    component=dep.get("fileName",""),
                    fix=(f"Update {dep.get('fileName','dep')} to a patched version. "
                         f"https://nvd.nist.gov/vuln/detail/{cve}"),
                    refs=[r.get("url","") for r in v.get("references",[])],
                ))
        log.info("Dependency-Check: %d findings", len(results))
        return results

    @staticmethod
    def _cvss(v):
        for k in ("cvssv3","cvssv2"):
            d = v.get(k, {})
            if isinstance(d, dict):
                s = d.get("baseScore") or d.get("score")
                if s: return float(s)
        return 5.0

# ── Trivy ─────────────────────────────────────────────────────────────────────
class TrivyAdapter:
    def __init__(self, path): self.path = Path(path)

    def collect(self):
        raw = json.loads(self.path.read_text())
        results = []
        for result in raw.get("Results", []):
            target = result.get("Target","")
            for v in result.get("Vulnerabilities",[]) or []:
                cve = v.get("VulnerabilityID","")
                pkg = v.get("PkgName","")
                installed = v.get("InstalledVersion","")
                fixed = v.get("FixedVersion","latest available version")
                results.append(vuln(
                    vid=cve or f"TRIVY-{len(results)}",
                    title=f"{cve}: {v.get('Title','Container Vulnerability')}",
                    desc=v.get("Description",""), sev=v.get("Severity","MEDIUM"),
                    cvss=self._cvss(v), tool="trivy", cve=cve,
                    component=f"{pkg}@{installed}", file_path=target,
                    fix=f"Upgrade {pkg} from {installed} to {fixed}.",
                    refs=v.get("References",[]),
                ))
        log.info("Trivy: %d findings", len(results))
        return results

    @staticmethod
    def _cvss(v):
        for src_data in v.get("CVSS",{}).values():
            for key in ("V3Score","V2Score"):
                if src_data.get(key): return float(src_data[key])
        return 5.0

# ── OWASP ZAP ─────────────────────────────────────────────────────────────────
class ZAPAdapter:
    RISK_CVSS = {"High":8.0,"Medium":5.5,"Low":2.5,"Informational":0.5}

    def __init__(self, zap_host, target_url):
        self.zap = zap_host.rstrip("/")
        self.target = target_url

    def collect(self):
        log.info("ZAP: spidering %s", self.target)
        self._spider()
        log.info("ZAP: active scanning %s", self.target)
        self._ascan()
        alerts = http_get(
            f"{self.zap}/JSON/alert/view/alerts/"
            f"?baseurl={urllib.parse.quote(self.target)}&start=0&count=10000"
        ).get("alerts", [])
        results = []
        for a in alerts:
            risk = a.get("risk","Medium")
            results.append(vuln(
                vid=f"ZAP-{a.get('pluginId',len(results))}",
                title=a.get("alert","ZAP Finding"),
                desc=a.get("description",""), sev=risk,
                cvss=self.RISK_CVSS.get(risk, 5.0), tool="owasp-zap",
                component=a.get("url",""), file_path=a.get("url",""),
                fix=a.get("solution",""), refs=[a.get("reference","")],
            ))
        log.info("ZAP: %d alerts", len(results))
        return results

    def _spider(self):
        data = http_get(f"{self.zap}/JSON/spider/action/scan/"
                        f"?url={urllib.parse.quote(self.target)}&recurse=true")
        self._poll("spider", data.get("scan","0"))

    def _ascan(self):
        data = http_get(f"{self.zap}/JSON/ascan/action/scan/"
                        f"?url={urllib.parse.quote(self.target)}&recurse=true")
        self._poll("ascan", data.get("scan","0"))

    def _poll(self, scan_type, scan_id, timeout=300):
        deadline = time.time() + timeout
        while time.time() < deadline:
            d = http_get(f"{self.zap}/JSON/{scan_type}/view/status/?scanId={scan_id}")
            progress = int(d.get("status",0))
            log.info("ZAP %s: %d%%", scan_type, progress)
            if progress >= 100: return
            time.sleep(5)
        log.warning("ZAP %s timed out", scan_type)

# ── Output ────────────────────────────────────────────────────────────────────
def write_report(vulns, output_path, tool_name):
    report = {
        "schema_version": "1.0", "tool": tool_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(vulns), "vulnerabilities": vulns,
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(report, indent=2))
    log.info("Written %s (%d vulnerabilities)", output_path, len(vulns))

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="DevSecOps Security Orchestrator")
    p.add_argument("--tool", required=True,
                   choices=["sonarqube","dependency-check","trivy","zap"])
    p.add_argument("--output", required=True)
    p.add_argument("--input")
    p.add_argument("--sonar-host"); p.add_argument("--sonar-token")
    p.add_argument("--sonar-project")
    p.add_argument("--zap-host"); p.add_argument("--target-url")
    args = p.parse_args()

    if args.tool == "sonarqube":
        vulns = SonarQubeAdapter(args.sonar_host, args.sonar_token, args.sonar_project).collect()
    elif args.tool == "dependency-check":
        vulns = DependencyCheckAdapter(args.input).collect()
    elif args.tool == "trivy":
        vulns = TrivyAdapter(args.input).collect()
    elif args.tool == "zap":
        vulns = ZAPAdapter(args.zap_host, args.target_url).collect()

    write_report(vulns, args.output, args.tool)

if __name__ == "__main__":
    main()
