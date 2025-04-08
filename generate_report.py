import json
import os
from datetime import datetime

def group_by_plugin(data):
    grouped = {}
    for filepath, vulns in data.items():
        parts = filepath.split(os.sep)
        plugin = parts[0] if len(parts) > 1 else "unknown"
        grouped.setdefault(plugin, {})[filepath] = vulns
    return grouped

def generate_html_report(data, output_file="report.html"):
    grouped_data = group_by_plugin(data)

    html = """<!DOCTYPE html>
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
    </style>
</head>
<body>
    <h1>🔎 WordPress Plugin Vulnerability Report</h1>
    <p>Generated on {date}</p>
""".format(date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if not grouped_data:
        html += "<p>No vulnerabilities detected.</p>"
    else:
        for plugin, files in grouped_data.items():
            html += f'<h2>📦 Plugin: {plugin}</h2>'
            for filepath, vulns in files.items():
                html += f'<div class="file-block">'
                html += f'<h3>📄 File: {filepath}</h3>'
                for vuln_type, issues in vulns.items():
                    html += f'<h4 class="vuln-type">🛑 {vuln_type} ({len(issues)})</h4>'
                    html += "<table><tr><th>Line</th><th>Code</th></tr>"
                    for line_num, code in issues:
                        code_escaped = (code.replace("&", "&amp;")
                                            .replace("<", "&lt;")
                                            .replace(">", "&gt;"))
                        html += f"<tr><td>{line_num}</td><td><pre>{code_escaped}</pre></td></tr>"
                    html += "</table>"
                html += "</div>"

    html += """
    <div class="footer">
        Vulnerability Scanner © {year}
    </div>
</body>
</html>
""".format(year=datetime.now().year)

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