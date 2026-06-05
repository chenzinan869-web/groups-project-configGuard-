import json
from datetime import datetime

def export_json(findings, file_path, output_path="scan_results.json"):
    report = {
        "file_scanned": file_path,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_issues": len(findings),
        "summary": {
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW")
        },
        "findings": findings
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n✅ Results exported to {output_path}")


def export_html(findings, file_path, output_path="scan_results.html"):
    high   = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low    = sum(1 for f in findings if f["severity"] == "LOW")

    rows = ""
    for finding in findings:
        severity = finding["severity"]
        if severity == "HIGH":
            colour = "#e74c3c"
        elif severity == "MEDIUM":
            colour = "#f39c12"
        else:
            colour = "#2ecc71"

        rows += f"""
        <tr>
            <td><span style="color:{colour}; font-weight:bold;">{severity}</span></td>
            <td>{finding['rule']}</td>
            <td>{finding['service']}</td>
            <td>{finding['description']}</td>
            <td>{finding['fix']}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ConfigGuard Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #1e1e2e; color: #cdd6f4; padding: 40px; }}
        h1 {{ color: #cba6f7; }}
        .meta {{ color: #a6adc8; margin-bottom: 30px; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .badge {{ padding: 10px 20px; border-radius: 8px; font-weight: bold; font-size: 16px; }}
        .high {{ background-color: #e74c3c; color: white; }}
        .medium {{ background-color: #f39c12; color: white; }}
        .low {{ background-color: #2ecc71; color: white; }}
        .total {{ background-color: #6c7086; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background-color: #313244; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #313244; }}
        tr:hover {{ background-color: #2a2a3d; }}
    </style>
</head>
<body>
    <h1>🛡️ ConfigGuard Scan Report</h1>
    <div class="meta">
        <p><strong>File scanned:</strong> {file_path}</p>
        <p><strong>Scan date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    <div class="summary">
        <div class="badge high">HIGH: {high}</div>
        <div class="badge medium">MEDIUM: {medium}</div>
        <div class="badge low">LOW: {low}</div>
        <div class="badge total">TOTAL: {len(findings)}</div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Service</th>
                <th>Description</th>
                <th>Fix</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n✅ Results exported to {output_path}")