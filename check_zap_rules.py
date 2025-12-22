#!/usr/bin/env python3
import json
from pathlib import Path

RULES_FILE = ROOT / ".zap" / "rules.tsv"
# tuỳ tên file JSON thực tế ZAP tạo:
REPORT_FILE = Path("report_json.json")  # nếu khác bạn sửa lại

def load_rules(path: Path):
    rules = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            rule_id, threshold, risk = parts[:3]
            rules[rule_id.strip()] = {
                "threshold": threshold.strip().upper(),
                "risk": risk.strip().upper(),
            }
    return rules

def main():
    if not RULES_FILE.is_file():
        print(f"[!] Rules file not found: {RULES_FILE}")
        raise SystemExit(1)

    if not REPORT_FILE.is_file():
        print(f"[!] ZAP report JSON not found: {REPORT_FILE}")
        raise SystemExit(1)

    rules = load_rules(RULES_FILE)
    data = json.loads(REPORT_FILE.read_text(encoding="utf-8"))

    
    alerts = []
    for site in data.get("site", []):
        alerts.extend(site.get("alerts", []))

    fail_issues = []
    warn_issues = []

    for a in alerts:
        plugin_id = str(a.get("pluginId"))
        risk = a.get("risk", "").upper()
        name = a.get("alert", "")

        rule = rules.get(plugin_id)
        if not rule:
            continue  

        threshold = rule["threshold"]  # FAIL / WARN / OFF

        if threshold == "OFF":
            continue

        entry = f"{plugin_id} [{risk}] {name}"

        if threshold == "FAIL":
            fail_issues.append(entry)
        elif threshold == "WARN":
            warn_issues.append(entry)

    if warn_issues:
        print("=== ZAP WARNINGS ===")
        for w in warn_issues:
            print("WARN:", w)

    if fail_issues:
        print("=== ZAP FAILURES (HIGH RISK MATCHED FAIL POLICY) ===")
        for f in fail_issues:
            print("FAIL:", f)
        # Đây là chỗ làm fail *toàn bộ job ZAP*
        raise SystemExit(1)

    print("ZAP check passed: no FAIL-level issues found.")

if __name__ == "__main__":
    main()
