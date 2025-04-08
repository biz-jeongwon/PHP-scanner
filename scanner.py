import os
import re
import json
from collections import defaultdict

vulnerability_patterns = {
    "SQL Injection": {
        "exec": [r"mysql_query\s*\(", r"mysqli_query\s*\(", r"\$pdo\s*->\s*query\s*\("],
        "input": [r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE"]
    },
    "XSS": {
        "exec": [r"echo", r"print"],
        "input": [r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE"]
    },
    "LFI": {
        "exec": [r"(include|require)(_once)?\s*\(", r"file_get_contents\s*\("],
        "input": [r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE"]
    },
    "RCE": {
        "exec": [r"system\s*\(", r"exec\s*\(", r"shell_exec\s*\(", r"passthru\s*\("],
        "input": [r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE"]
    },
    "SSRF": {
        "exec": [r"curl_exec\s*\(", r"file_get_contents\s*\(", r"fopen\s*\(", r"fsockopen\s*\("],
        "input": [r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE"]
    }
}

def find_php_files(root_dir):
    php_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".php"):
                php_files.append(os.path.join(root, file))
    return php_files

def scan_file_for_vulns(filepath):
    results = defaultdict(list)
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            for vuln_type, patterns in vulnerability_patterns.items():
                if any(re.search(p, line) for p in patterns["exec"]) and any(re.search(ip, line) for ip in patterns["input"]):
                    results[vuln_type].append({"line": i + 1, "content": line.strip()})
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return results

def main_scan():
    root_dir = "plugins-wp"
    php_files = find_php_files(root_dir)
    all_results = {v: {} for v in vulnerability_patterns.keys()}
    total_files = len(php_files)
    vuln_counts = {v: 0 for v in vulnerability_patterns}

    for file in php_files:
        file_results = scan_file_for_vulns(file)
        for vuln_type, findings in file_results.items():
            if findings:
                all_results[vuln_type][file] = findings
                vuln_counts[vuln_type] += 1

    return all_results, vuln_counts, total_files

# 콘솔 출력 및 JSON 저장
def generate_report():
    results, vuln_counts, total_files = main_scan()
    output_dir = "scan_results"
    os.makedirs(output_dir, exist_ok=True)

    for vuln_type, data in results.items():
        json_path = os.path.join(output_dir, f"{vuln_type.lower().replace(' ', '_')}_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    print("\n📦 Scan Summary:\n")
    for vuln_type, count in vuln_counts.items():
        percent = (count / total_files * 100) if total_files else 0
        print(f"🛡️  {vuln_type}: {count}/{total_files} files ({percent:.2f}%)")

    print("\n✅ Reports saved to 'scan_results/' directory.")

generate_report()