import os
import re
import json

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_ascii_art():
    ascii_art = r"""
██████╗ ██╗  ██╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██║  ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝███████║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██╔══██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║  ██║██║         ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""
    print(f"{YELLOW}{ascii_art}{RESET}")

def find_php_files(root_dir):
    php_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".php"):
                php_files.append(os.path.join(root, file))
    return php_files

def collect_user_input_vars(code_lines):
    tainted_vars = {}
    assign_pattern = re.compile(r'\$(\w+)\s*=\s*(.+);')
    sources = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE', r'\$_FILES']
    escape_functions = r'(htmlspecialchars|htmlentities|esc_html|esc_attr|wp_kses|sanitize_text_field|filter_var|absint|give_clean)'

    for i, line in enumerate(code_lines):
        match = assign_pattern.search(line)
        if match:
            var_name, value = match.groups()
            if any(re.search(src, value) for src in sources):
                if not re.search(escape_functions, value, re.IGNORECASE):
                    tainted_vars[var_name] = line.strip()  # <== trace 기록
    return tainted_vars

def detect_vulns(code_lines, tainted_vars):
    vuln_results = {
        "SQLi": [],
        "XSS": [],
        "LFI": [],
        "RCE": [],
        "SSRF": [],
        "CSRF": []
    }

    sqli_patterns = [r"mysql_query\s*\(", r"mysqli_query\s*\(", r"\$pdo\s*->\s*query\s*\("]
    xss_patterns = [r"echo", r"print"]
    lfi_patterns = [r"include\s*\(", r"require\s*\(", r"include_once\s*\(", r"require_once\s*\("]
    rce_patterns = [r"eval\s*\(", r"system\s*\(", r"exec\s*\(", r"shell_exec\s*\(", r"passthru\s*\("]
    ssrf_patterns = [r"file_get_contents\s*\(", r"curl_exec", r"curl_init"]
    escape_functions = r'htmlspecialchars|htmlentities|esc_html|esc_attr|absint|strtotime|give_clean'
    tainted_sources = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE', r'\$_FILES']

    variable_map = tainted_vars.copy()
    function_def_pattern = re.compile(r'function\s+(\w+)\s*\((.*?)\)\s*\{?')

    in_form = False
    inside_function = None
    function_blocks = {}

    for i, line in enumerate(code_lines):
        stripped = line.strip().lower()
        if "<form" in stripped:
            in_form = True
        if "</form>" in stripped:
            in_form = False

        func_def_match = function_def_pattern.search(line)
        if func_def_match:
            func_name = func_def_match.group(1)
            inside_function = func_name
            function_blocks[func_name] = []
        elif inside_function:
            function_blocks[inside_function].append((i, line))
            if line.strip() == "}":
                inside_function = None

    for i, line in enumerate(code_lines):
        assign_match = re.search(r'\$(\w+)\s*=\s*(\$[\w\[\]\'"]+);', line)
        if assign_match:
            var_name, source = assign_match.groups()
            src_var = source.strip('$')
            if src_var in variable_map:
                variable_map[var_name] = variable_map[src_var]

        for vuln_type, patterns in {
            "SQLi": sqli_patterns,
            "XSS": xss_patterns,
            "LFI": lfi_patterns,
            "RCE": rce_patterns,
            "SSRF": ssrf_patterns
        }.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    for var, trace in variable_map.items():
                        if f"${var}" in line:
                            if vuln_type == "XSS" and re.search(escape_functions, line, re.IGNORECASE):
                                continue
                            vuln_results[vuln_type].append({
                                "line": i + 1,
                                "code": line.strip(),
                                "trace": trace
                            })

        if re.search(r'\$_POST', line):
            lower_line = line.lower()
            if in_form:
                if not re.search(r'csrf|nonce|token|wp_nonce', lower_line) and not re.search(r'check.*csrf|verify.*token', lower_line):
                    vuln_results["CSRF"].append({"line": i + 1, "code": line.strip()})

    for func_name, func_lines in function_blocks.items():
        for idx, line in func_lines:
            for vuln_type, patterns in {
                "SQLi": sqli_patterns,
                "XSS": xss_patterns,
                "LFI": lfi_patterns,
                "RCE": rce_patterns,
                "SSRF": ssrf_patterns
            }.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        for var, trace in variable_map.items():
                            if f"${var}" in line:
                                if vuln_type == "XSS" and re.search(escape_functions, line, re.IGNORECASE):
                                    continue
                                vuln_results[vuln_type].append({
                                    "line": idx + 1,
                                    "code": line.strip(),
                                    "trace": trace,
                                    "function": func_name
                                })

    return vuln_results

def analyze_php_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    tainted_vars = collect_user_input_vars(lines)
    return detect_vulns(lines, tainted_vars)

def print_progress(current, total):
    percent = int((current / total) * 100)
    print(f"{CYAN}[+] Progress: {percent}% ({current}/{total}){RESET}", end='\r')

def main():
    print_ascii_art()

    plugins_dir = "plugins-wp"
    php_files = find_php_files(plugins_dir)
    total_files = len(php_files)
    scan_result = {}

    for i, filepath in enumerate(php_files, 1):
        result = analyze_php_file(filepath)
        filtered = {k: v for k, v in result.items() if v}
        if filtered:
            scan_result[filepath] = filtered
        print_progress(i, total_files)

    print(f"\n{GREEN}[+] Scan Complete.{RESET}")
    print(f"{YELLOW}[+] Vulnerable files detected: {len(scan_result)}{RESET}")

    with open("scan_result.json", "w", encoding='utf-8') as f:
        json.dump(scan_result, f, indent=2, ensure_ascii=False)

    print(f"{BLUE}[+] Results saved to scan_result.json{RESET}")

    vuln_count = {
        "SQLi": 0,
        "XSS": 0,
        "LFI": 0,
        "RCE": 0,
        "SSRF": 0,
        "CSRF": 0
    }

    for file_result in scan_result.values():
        for vuln_type, findings in file_result.items():
            vuln_count[vuln_type] += len(findings)

    print(f"\n{GREEN}[+] Vulnerability Summary:{RESET}")
    for vuln_type, count in vuln_count.items():
        color = RED if count > 0 else GREEN
        print(f"    {color}[+] {vuln_type}: {count}{RESET}")

if __name__ == "__main__":
    main()