#!/usr/bin/env python3
import json
from pathlib import Path
from csv import DictReader

ROOT = Path(__file__).parent
RULES_FILE = ROOT / ".zap" / "rules.tsv"
# tuỳ tên file JSON thực tế ZAP tạo:
REPORT_FILE = ROOT / "report_json.json"  # nếu khác bạn sửa lại

#print("DEBUG: using report file:", REPORT_FILE.resolve())

if not REPORT_FILE.exists():
    raise SystemExit(f"DEBUG ERROR: report file {REPORT_FILE} not found")

data = json.loads(REPORT_FILE.read_text(encoding="utf-8"))

#print("DEBUG: sites:", [s.get('name') for s in data.get('site', [])])
#print("DEBUG: total alerts:", len(data.get('site', [])[0].get('alerts', [])) if data.get('site') else 0)

# 1. Lấy danh sách site đúng định dạng
sites = data.get("site", [])
#print("DEBUG: number of sites:", len(sites))

for idx, s in enumerate(sites):
    print(f"DEBUG: site[{idx}] name:", s.get("@name"))
    print(f"DEBUG: site[{idx}] alerts:", len(s.get("alerts", [])))

# 2. Gom tất cả alerts
all_alerts = []
for s in sites:
    all_alerts.extend(s.get("alerts", []))

#print("DEBUG: total alerts:", len(all_alerts))
#print("DEBUG: first 3 alerts names:", [a.get("alert") for a in all_alerts[:3]])

# 3. Đọc rules.tsv (giả sử dùng pluginid \t threshold)
rules = {}
if RULES_FILE.exists():
    with RULES_FILE.open(encoding="utf-8") as f:
        reader = DictReader(
            f, fieldnames=["pluginid", "threshold"], delimiter="\t"
        )
        for row in reader:
            pid = (row["pluginid"] or "").strip()
            thr = (row["threshold"] or "").strip().upper()
            if not pid or pid.startswith("#"):
                continue
            rules[pid] = thr
else:
    print("DEBUG: rules file not found:", RULES_FILE)
    rules = {}

#print("DEBUG: loaded rules:", rules)

# 4. Map riskcode -> risk level text để dễ so
risk_map = {
    "0": "INFORMATIONAL",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
}

failures = []

for a in all_alerts:
    pid = a.get("pluginid")
    name = a.get("alert")
    riskcode = (a.get("riskcode") or "").strip()
    risk = risk_map.get(riskcode, f"UNKNOWN({riskcode})")
    rule = rules.get(pid)

    #print(f"DEBUG: alert pluginid={pid}, name={name}, risk={risk}, rule={rule}")

    # Ví dụ: FAIL nếu rule=FAIL và risk >= MEDIUM
    if rule == "FAIL" and risk in {"MEDIUM", "HIGH"}:
        failures.append(f"{name} (pluginid={pid}, risk={risk})")

if failures:
    print("ZAP check FAILED; FAIL-level issues:")
    for f in failures:
        print(" -", f)
    raise SystemExit(1)
else:
    print("ZAP check passed: no FAIL-level issues found.")