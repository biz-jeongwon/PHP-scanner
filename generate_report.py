import json
import os
import re
from datetime import datetime

def group_by_plugin(data):
    grouped = {}
    for filepath, vulns in data.items():
        parts = filepath.split(os.sep)
        plugin = parts[1] if len(parts) > 2 else parts[0]
        grouped.setdefault(plugin, {})[filepath] = vulns
    return grouped

def highlight_tainted_vars(code, tainted_vars):
    for var in tainted_vars:
        pattern = re.escape(var)
        code = re.sub(pattern, f'<span class="tainted-var">{var}</span>', code)
    return code

def generate_html_report(data, output_file="report.html"):
    grouped_data = group_by_plugin(data)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WordPress Plugin Vulnerability Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f6f8fa;
            margin: 20px;
            color: #333;
        }}
        h1 {{
            color: #1a73e8;
        }}
        h2 {{
            color: #333;
            margin-top: 40px;
        }}
        h3 {{
            color: #555;
        }}
        .file-block {{
            margin-bottom: 30px;
            padding: 15px;
            border-radius: 8px;
            background: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.05);
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin-top: 10px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            font-size: 14px;
            vertical-align: top;
        }}
        th {{
            background-color: #f2f2f2;
            text-align: left;
        }}
        .vuln-type {{
            font-weight: bold;
            color: #d93025;
        }}
        .footer {{
            margin-top: 50px;
            font-size: 12px;
            text-align: center;
            color: #999;
        }}
        .tainted-var {{
            color: #1a73e8;
            font-weight: bold;
        }}
        pre {{
            margin: 0;
            white-space: pre-wrap;
        }}
        .sub-detail {{
            background-color: #fafafa;
            font-size: 13px;
            border-top: 0;
        }}
    </style>
</head>
<body>
    <h1>🔎 WordPress Plugin Vulnerability Report</h1>
    <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
"""

    if not grouped_data:
        html += "<p>No vulnerabilities detected.</p>"
    else:
        for plugin, files in grouped_data.items():
            html += f'<h2>📦 Plugin: {plugin}</h2>'
            for filepath, vulns in files.items():
                html += f'<div class="file-block">'
                html += f'<h3>📄 File: {filepath}</h3>'
                for vuln_type, issues in vulns.items():
                    if not issues:
                        continue
                    html += f'<h4 class="vuln-type">🛑 {vuln_type} ({len(issues)})</h4>'
                    html += "<table><tr><th>Line</th><th>Detail</th></tr>"
                    for issue in issues:
                        line_num = issue.get("line", "-")
                        code = issue.get("code", "")
                        trace = issue.get("trace", [])
                        function = issue.get("function", "")

                        tainted_vars = [t for t in trace if isinstance(t, str) and t.startswith("$")]
                        code_escaped = highlight_tainted_vars(
                            code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
                            tainted_vars
                        )

                        html += f"<tr><td>{line_num}</td><td><pre>{code_escaped}</pre></td></tr>"

                        if trace:
                            html += f"<tr><td></td><td class='sub-detail'><strong>Trace:</strong> {trace}</td></tr>"
                        if function:
                            html += f"<tr><td></td><td class='sub-detail'><strong>Function:</strong> {function}</td></tr>"

                    html += "</table>"
                html += "</div>"

    html += f"""
    <div class="footer">
        Vulnerability Scanner © {datetime.now().year}
    </div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML report saved as: {output_file}")

def main():
    input_file = "scan_result.json"
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        generate_html_report(data)
    except Exception as e:
        print(f"[-] Failed to generate report: {e}")

if __name__ == "__main__":
    main()