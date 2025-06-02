import os
import re
import json
import multiprocessing as mp
from functools import partial

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

# 정교한 취약점 패턴 정의
PATTERNS = {
    "SQLi": [
        # 기본적인 SQL 함수들
        r"mysql_query\s*\(\s*[^,]*\$[^,]*\)",
        r"mysqli_query\s*\(\s*[^,]*\$[^,]*\)",
        r"\$[a-zA-Z0-9_]+\s*->\s*query\s*\(\s*[^,]*\$[^,]*\)",
        # PDO 쿼리
        r"->prepare\s*\(\s*['\"][^'\"]*\$[^'\"]*['\"]\s*\)",
        r"->query\s*\(\s*['\"][^'\"]*\$[^'\"]*['\"]\s*\)",
        # 위험한 문자열 연결
        r"SELECT.+\$[^,;]*[^=!<>]\s*(FROM|WHERE)",
        r"INSERT.+\$[^,;]*[^=!<>]\s*(INTO|VALUES)",
        r"UPDATE.+\$[^,;]*[^=!<>]\s*(SET|WHERE)",
        r"DELETE.+\$[^,;]*[^=!<>]\s*(FROM|WHERE)"
    ],
    "XSS": [
        # 직접 출력
        r"echo\s+\$[^;]*;",
        r"print\s+\$[^;]*;",
        r"print_r\s*\([^)]*\$[^)]*\)",
        r"var_dump\s*\([^)]*\$[^)]*\)",
        # HTML 내 변수 출력
        r"<[^>]*\$[^>]*>",
        r"=[\"']\s*\$[^\"']*[\"']",
        # JavaScript 내 변수 출력
        r"<script[^>]*>[^<]*\$[^<]*</script>",
        r"javascript:[^;]*\$[^;]*"
    ],
    "LFI": [
        # 파일 포함
        r"include\s*\(\s*\$[^)]+\)",
        r"require\s*\(\s*\$[^)]+\)",
        r"include_once\s*\(\s*\$[^)]+\)",
        r"require_once\s*\(\s*\$[^)]+\)",
        # 파일 조작
        r"fopen\s*\(\s*\$[^,)]+[,)]",
        r"file_get_contents\s*\(\s*\$[^)]+\)",
        r"file_put_contents\s*\(\s*\$[^,)]+[,)]",
        r"readfile\s*\(\s*\$[^)]+\)",
        # 경로 조작
        r"\.\./.*\$[^/]*",
        r"/(?:etc|usr|bin|root).*\$[^/]*"
    ],
    "RCE": [
        # 명령어 실행
        r"eval\s*\(\s*\$[^)]+\)",
        r"system\s*\(\s*\$[^)]+\)",
        r"exec\s*\(\s*\$[^)]+\)",
        r"shell_exec\s*\(\s*\$[^)]+\)",
        r"passthru\s*\(\s*\$[^)]+\)",
        r"proc_open\s*\(\s*\$[^)]+\)",
        r"popen\s*\(\s*\$[^)]+\)",
        r"`[^`]*\$[^`]*`",
        # 동적 함수 호출
        r"call_user_func\s*\(\s*\$[^)]+\)",
        r"call_user_func_array\s*\(\s*\$[^)]+\)",
        r"create_function\s*\([^)]*\$[^)]*\)"
    ],
    "SSRF": [
        # URL 요청
        r"curl_exec\s*\(\s*[^)]*\$[^)]*\)",
        r"curl_setopt\s*\([^,]*,\s*CURLOPT_URL\s*,\s*\$[^)]*\)",
        r"file_get_contents\s*\(\s*\$[^)]+\)",
        r"fsockopen\s*\(\s*\$[^,)]+[,)]",
        r"fopen\s*\(\s*['\"]https?://[^'\"]*\$[^'\"]*['\"]\s*[,)]",
        # WordPress 특화
        r"wp_remote_get\s*\(\s*\$[^)]+\)",
        r"wp_remote_post\s*\(\s*\$[^)]+\)",
        r"wp_remote_request\s*\(\s*\$[^)]+\)"
    ]
}

# 안전한 함수 및 처리 패턴
SAFE_PATTERNS = {
    "SQLi": [
        r"mysqli_real_escape_string",
        r"mysql_real_escape_string",
        r"addslashes",
        r"prepare",
        r"bindParam",
        r"bindValue"
    ],
    "XSS": [
        r"htmlspecialchars",
        r"htmlentities",
        r"strip_tags",
        r"esc_html",
        r"esc_attr",
        r"esc_url",
        r"sanitize_text_field",
        r"wp_kses"
    ],
    "LFI": [
        r"basename",
        r"realpath",
        r"pathinfo",
        r"sanitize_file_name"
    ],
    "RCE": [
        r"escapeshellarg",
        r"escapeshellcmd"
    ],
    "SSRF": [
        r"wp_http_validate_url",
        r"esc_url",
        r"wp_validate_redirect"
    ]
}

# 컴파일된 정규표현식 패턴
COMPILED_PATTERNS = {
    vuln_type: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for vuln_type, patterns in PATTERNS.items()
}

COMPILED_SAFE_PATTERNS = {
    vuln_type: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for vuln_type, patterns in SAFE_PATTERNS.items()
}

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

def is_sanitized(line: str, vuln_type: str) -> bool:
    """주어진 라인이 적절히 sanitize 되었는지 확인"""
    return any(pattern.search(line) for pattern in COMPILED_SAFE_PATTERNS.get(vuln_type, []))

def collect_user_input_vars(code_lines):
    """사용자 입력 변수 추적"""
    tainted_vars = {}
    var_pattern = re.compile(r'\$(\w+)\s*=\s*(.+);')
    sources = [
        r'\$_GET',
        r'\$_POST',
        r'\$_REQUEST',
        r'\$_COOKIE',
        r'\$_FILES',
        r'\$_SERVER\[.*(REQUEST|QUERY|POST|GET|HTTP).*\]'
    ]
    source_patterns = [re.compile(s) for s in sources]
    
    for i, line in enumerate(code_lines):
        match = var_pattern.search(line)
        if match:
            var_name, value = match.groups()
            if any(pattern.search(value) for pattern in source_patterns):
                tainted_vars[var_name] = {
                    'line': i + 1,
                    'code': line.strip(),
                    'source': value
                }
    
    # 변수 전파 추적
    changed = True
    while changed:
        changed = False
        for i, line in enumerate(code_lines):
            match = var_pattern.search(line)
            if match:
                var_name, value = match.groups()
                for tainted_var in tainted_vars:
                    if f'${tainted_var}' in value and var_name not in tainted_vars:
                        tainted_vars[var_name] = {
                            'line': i + 1,
                            'code': line.strip(),
                            'source': f'from ${tainted_var}'
                        }
                        changed = True
    
    return tainted_vars

def detect_vulns(code_lines, tainted_vars):
    """취약점 탐지"""
    vuln_results = {
        "SQLi": [],
        "XSS": [],
        "LFI": [],
        "RCE": [],
        "SSRF": [],
        "CSRF": []
    }

    # CSRF 관련 변수들
    in_form = False
    has_csrf_token = False
    form_start_line = -1
    form_method = ""
    nonce_patterns = [
        r'wp_nonce_field\s*\(',
        r'wp_create_nonce\s*\(',
        r'wp_verify_nonce\s*\(',
        r'check_admin_referer\s*\(',
        r'check_ajax_referer\s*\(',
        r'<input[^>]*name=["\'](?:_wpnonce|nonce|csrf_token)["\'][^>]*>',
        r'add_query_arg\s*\(\s*["\']_wpnonce["\']'
    ]
    compiled_nonce_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in nonce_patterns]

    # 각 취약점 유형별 검사
    for i, line in enumerate(code_lines):
        # CSRF 컨텍스트 추적
        if '<form' in line.lower():
            in_form = True
            form_start_line = i
            # form method 확인
            method_match = re.search(r'method=["\'](\w+)["\']', line.lower())
            form_method = method_match.group(1) if method_match else "get"
            has_csrf_token = False

        # CSRF 토큰 체크
        if in_form:
            # 현재 라인에서 CSRF 보호 패턴 확인
            for pattern in compiled_nonce_patterns:
                if pattern.search(line):
                    has_csrf_token = True
                    break

        if '</form>' in line.lower():
            # POST form이고 CSRF 토큰이 없는 경우만 취약점으로 판단
            if form_method.lower() == "post" and not has_csrf_token:
                # 관리자 페이지는 제외 (WordPress는 자동으로 nonce를 추가함)
                is_admin_page = any('admin' in l.lower() for l in code_lines[max(0, form_start_line-5):form_start_line+5])
                if not is_admin_page:
                    vuln_results["CSRF"].append({
                        'line': form_start_line + 1,
                        'code': code_lines[form_start_line].strip(),
                        'description': 'POST form without CSRF protection'
                    })
            in_form = False
            has_csrf_token = False
            form_start_line = -1
            form_method = ""

        # 다른 취약점 검사
        for vuln_type, patterns in COMPILED_PATTERNS.items():
            if vuln_type == "CSRF":
                continue  # CSRF는 위에서 별도로 처리
            for pattern in patterns:
                if pattern.search(line):
                    for var_name, var_info in tainted_vars.items():
                        if f'${var_name}' in line and not is_sanitized(line, vuln_type):
                            vuln_results[vuln_type].append({
                                'line': i + 1,
                                'code': line.strip(),
                                'variable': var_name,
                                'source': var_info['source'],
                                'source_line': var_info['line']
                            })

    return vuln_results

def analyze_php_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        tainted_vars = collect_user_input_vars(lines)
        return filepath, detect_vulns(lines, tainted_vars)
    except Exception as e:
        return filepath, {"error": str(e)}

def process_chunk(files):
    results = {}
    for filepath in files:
        file_path, result = analyze_php_file(filepath)
        if any(result.values()):  # Only store if vulnerabilities were found
            results[file_path] = result
    return results

def print_progress(current, total):
    percent = int((current / total) * 100)
    print(f"{CYAN}[+] Progress: {percent}% ({current}/{total}){RESET}", end='\r')

def main():
    print_ascii_art()

    plugins_dir = "plugins-wp"
    php_files = find_php_files(plugins_dir)
    total_files = len(php_files)
    
    # Determine optimal chunk size based on CPU count
    cpu_count = mp.cpu_count()
    chunk_size = max(1, total_files // (cpu_count * 2))
    chunks = [php_files[i:i + chunk_size] for i in range(0, len(php_files), chunk_size)]
    
    scan_result = {}
    with mp.Pool(processes=cpu_count) as pool:
        for i, chunk_result in enumerate(pool.imap_unordered(process_chunk, chunks)):
            scan_result.update(chunk_result)
            print_progress(min((i + 1) * chunk_size, total_files), total_files)

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
            if vuln_type != "error":
                vuln_count[vuln_type] += len(findings)

    print(f"\n{GREEN}[+] Vulnerability Summary:{RESET}")
    for vuln_type, count in vuln_count.items():
        color = RED if count > 0 else GREEN
        print(f"    {color}[+] {vuln_type}: {count}{RESET}")

if __name__ == "__main__":
    main()