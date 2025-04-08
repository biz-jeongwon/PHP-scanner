import os
import re
import json

# 콘솔 색상 정의
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

# PHP 파일 찾기
def find_php_files(root_dir):
    php_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".php"):
                php_files.append(os.path.join(root, file))
    return php_files

# 취약점 탐지기
def detect_pattern(lines, vuln_patterns, input_patterns):
    result = []
    for i, line in enumerate(lines):
        if any(re.search(v, line) for v in vuln_patterns) and any(re.search(inp, line) for inp in input_patterns):
            result.append((i + 1, line.strip()))
    return result

def detect_sqli(lines):
    return detect_pattern(lines, [r"mysql_query\s*\(", r"mysqli_query\s*\(", r"\$pdo\s*->\s*query\s*\("],
                          [r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE"])

def detect_xss(lines):
    return detect_pattern(lines, [r"echo", r"print", r"\?>"],
                          [r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE"])

def detect_ssrf(lines):
    return detect_pattern(lines, [r"file_get_contents\s*\(", r"curl_exec", r"fsockopen"],
                          [r"\$_GET", r"\$_POST", r"\$_REQUEST"])

def detect_rce(lines):
    return detect_pattern(lines, [r"shell_exec", r"exec", r"passthru", r"system", r"`.*`"],
                          [r"\$_GET", r"\$_POST", r"\$_REQUEST"])

def detect_lfi(lines):
    return detect_pattern(lines, [r"include\s*\(", r"require\s*\(", r"include_once\s*\(", r"require_once\s*\("],
                          [r"\$_GET", r"\$_POST", r"\$_REQUEST"])

# PHP 파일 분석
def analyze_php_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    return {
        "sqli": detect_sqli(lines),
        "xss": detect_xss(lines),
        "ssrf": detect_ssrf(lines),
        "rce": detect_rce(lines),
        "lfi": detect_lfi(lines)
    }

# 메인 실행
def main():
    plugin_dir = "plugins-wp"
    php_files = find_php_files(plugin_dir)
    total_files = len(php_files)
    vuln_count = {"sqli": 0, "xss": 0, "ssrf": 0, "rce": 0, "lfi": 0}
    filtered_results = {}

    print(f"\n{Colors.BOLD}[*] Starting vulnerability scan on {total_files} PHP files...{Colors.RESET}\n")

    for idx, file in enumerate(php_files, 1):
        vulns = analyze_php_file(file)
        if any(vulns[v] for v in vulns):  # 취약점이 하나라도 있으면 저장
            filtered_results[file] = vulns
            for key in vuln_count:
                vuln_count[key] += len(vulns[key])

        percent = (idx / total_files) * 100
        print(f"\r{Colors.BLUE}[*] Progress: {int(percent)}% ({idx}/{total_files}){Colors.RESET}", end='', flush=True)

    print(f"\n\n{Colors.BOLD}[+] Scan Complete! Summary:{Colors.RESET}")
    total_issues = sum(vuln_count.values())
    if total_issues == 0:
        print(f"{Colors.GREEN}✅ No vulnerabilities detected!{Colors.RESET}")
    else:
        for k, v in vuln_count.items():
            pct = (v / total_issues) * 100 if total_issues else 0
            print(f"{Colors.YELLOW}- {k.upper()}: {v} ({pct:.1f}%) {Colors.RESET}")

    with open("scan_result.json", "w", encoding="utf-8") as f:
        json.dump(filtered_results, f, indent=2, ensure_ascii=False)

    print(f"\n{Colors.GREEN}[+] Results saved to 'scan_result.json'{Colors.RESET}")

if __name__ == "__main__":
    main()
