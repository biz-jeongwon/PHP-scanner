import os
import re

def find_php_files(root_dir):
    php_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".php"):
                php_files.append(os.path.join(root, file))
    return php_files

def detect_sql_injection(code_lines):
    vulnerable_lines = []
    sql_exec_patterns = [
        r"mysql_query\s*\(",
        r"mysqli_query\s*\(",
        r"\$pdo\s*->\s*query\s*\(",
    ]
    user_input_patterns = [
        r"\$_GET",
        r"\$_POST",
        r"\$_REQUEST",
        r"\$_COOKIE",
    ]

    for i, line in enumerate(code_lines):
        if any(re.search(sql_pattern, line) for sql_pattern in sql_exec_patterns):
            if any(re.search(input_pattern, line) for input_pattern in user_input_patterns):
                vulnerable_lines.append((i + 1, line.strip()))
    return vulnerable_lines

def analyze_php_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    return detect_sql_injection(lines)

def main():
    plugins_dir = "plugins-wp"
    php_files = find_php_files(plugins_dir)

    print("\n[!] Scanning PHP files for potential SQL Injection vulnerabilities...\n")
    for file in php_files:
        vulnerabilities = analyze_php_file(file)
        if vulnerabilities:
            print(f"\n[+] {file} - Potential Vulnerabilities:")
            for line_num, content in vulnerabilities:
                print(f"  [Line {line_num}] {content}")

if __name__ == "__main__":
    main()