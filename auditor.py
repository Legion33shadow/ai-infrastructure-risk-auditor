#!/usr/bin/env python3
"""
AI Infrastructure Risk Auditor
Scans a system's AI stack and produces a risk report.
Sources: LEGION /guard + /immune + /actuarial + /clauses
"""
import requests, json, datetime, hashlib, base64, subprocess
from pathlib import Path

def audit(providers: list, output_file: str = None) -> dict:
    today = datetime.datetime.utcnow().isoformat() + "Z"
    report = {"audited_at": today, "providers": providers, "findings": [], "risk_score": 0}
    
    for prov in providers:
        finding = {"provider": prov, "checks": {}}
        
        # Guard check
        try:
            r = requests.get(f"https://api.legion-api.com/guard?providers={prov}&since=2026-09-01", timeout=10)
            guard = r.json()
            pdata = guard.get("providers", {}).get(prov, {})
            finding["checks"]["guard"] = pdata.get("verdict", "UNKNOWN")
            if pdata.get("verdict") in ["HOLD","REVIEW"]: report["risk_score"] += 20
        except: finding["checks"]["guard"] = "ERROR"
        
        # Immune check
        try:
            r = requests.get(f"https://api.legion-api.com/immune?provider={prov}", timeout=10)
            immune = r.json().get("results", [{}])
            if immune: finding["checks"]["immunity"] = immune[0].get("immunity_score", 0)
        except: finding["checks"]["immunity"] = None
        
        # Actuarial
        try:
            r = requests.get(f"https://api.legion-api.com/actuarial?provider={prov}", timeout=10)
            rows = r.json().get("results", [])
            critical = next((x for x in rows if x.get("severity")=="critical"), {})
            finding["checks"]["expected_loss_usd"] = critical.get("expected_loss", 0)
            finding["checks"]["prob_incident_30d"] = critical.get("prob_30d", 0)
        except: pass
        
        # Clause risks
        try:
            r = requests.get(f"https://api.legion-api.com/clauses?provider={prov}&risk=HIGH", timeout=10)
            clauses = r.json().get("results", [])
            finding["checks"]["high_risk_clauses"] = len(clauses)
            if clauses: report["risk_score"] += len(clauses) * 5
        except: pass
        
        report["findings"].append(finding)
    
    report["risk_level"] = "CRITICAL" if report["risk_score"] > 60 else "HIGH" if report["risk_score"] > 30 else "MEDIUM" if report["risk_score"] > 10 else "LOW"
    
    if output_file:
        Path(output_file).write_text(json.dumps(report, indent=2))
        print(f"Report saved: {output_file}")
    
    return report

if __name__ == "__main__":
    import sys
    providers = sys.argv[1:] if len(sys.argv) > 1 else ["openai", "anthropic", "groq"]
    result = audit(providers, "/tmp/legion-audit.json")
    print(json.dumps({
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "providers_audited": len(result["findings"])
    }, indent=2))
