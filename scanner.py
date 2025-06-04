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
        # 기본적인 SQL 함수들 - 변수가 쿼리 문자열에 직접 들어가는 경우만
        r"mysql_query\s*\(\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE|UNION|JOIN).*\$[^'\"]+.*['\"]\s*\)",
        r"mysqli_query\s*\(\s*[^,]+,\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE|UNION|JOIN).*\$[^'\"]+.*['\"]\s*\)",
        r"\$[a-zA-Z0-9_]+\s*->\s*query\s*\(\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE|UNION|JOIN).*\$[^'\"]+.*['\"]\s*\)",
        # PDO 쿼리 - prepare statement가 아닌 직접 쿼리
        r"->query\s*\(\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE|UNION|JOIN).*\$[^'\"]+.*['\"]\s*\)",
        # 위험한 문자열 연결 - WHERE/SET 절에서 위험한 연산자와 함께 사용될 때만
        r"SELECT.+WHERE.*\$[^'\"]*['\"]\s*(?:=|LIKE|IN|>|<|>=|<=|<>|!=|BETWEEN|NOT)\s*(?:['\"].*['\"]\s*OR|AND|UNION|JOIN)",
        r"UPDATE.+SET.*\$[^'\"]*['\"]\s*=.*(?:OR|AND|UNION|JOIN)",
        r"DELETE.+WHERE.*\$[^'\"]*['\"]\s*(?:=|LIKE|IN|>|<|>=|<=|<>|!=|BETWEEN|NOT)\s*(?:['\"].*['\"]\s*OR|AND|UNION|JOIN)",
        # WordPress 특화 - 직접 변수 사용
        r"\$wpdb->query\s*\(\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE|UNION|JOIN).*\$[^'\"]+.*['\"]\s*\)"
    ],
    "XSS": [
        # HTML 태그 내 위험한 속성에서의 변수 사용
        r"<[^>]+(?:href|src|style|on\w+)\s*=\s*['\"]?\s*\$[^'\">\s]+['\"]?",
        # JavaScript 이벤트 핸들러나 인라인 스크립트에서의 변수 사용
        r"on(?:click|load|mouseover|submit|change)\s*=\s*['\"].*\$[^'\"]+['\"]",
        r"<script[^>]*>\s*.*(?:document\.write|innerHTML|outerHTML|eval)\s*\([^)]*\$[^)]*\)",
        # JSON 데이터에 직접 변수 포함 (JSON_HEX 플래그 없이)
        r"json_encode\s*\(\s*\$[^),]+(?!\s*,\s*JSON_HEX_(?:TAG|AMP|APOS|QUOT))[,)]",
        # WordPress 특화 - 안전하지 않은 출력
        r"_e\s*\(\s*\$[^,)]+\s*[,)](?!\s*,\s*['\"]\w+['\"]\s*\))",
        r"__\s*\(\s*\$[^,)]+\s*[,)](?!\s*,\s*['\"]\w+['\"]\s*\))"
    ],
    "LFI": [
        # 파일 포함 - 경로 조작 가능성이 높은 패턴만
        r"(?:include|require)(?:_once)?\s*\(\s*['\"]?\s*(?:\.\./|\\\\|\/var\/|\/etc\/|\/usr\/|\/root\/|\$_(?:GET|POST|REQUEST))[^'\"]*['\"]?\s*\)",
        # 파일 조작 - 위험한 디렉토리나 상대 경로 사용
        r"file_(?:get|put)_contents\s*\(\s*['\"]?\s*(?:\.\./|\\\\|\/var\/|\/etc\/|\/usr\/|\/root\/|\$_(?:GET|POST|REQUEST))[^'\"]*['\"]?\s*[,)]",
        # 위험한 경로 패턴과 변수 결합
        r"[\"']\s*\.\s*\$[^;]+\s*\.\s*[\"']\s*.*(?:\.\.\/|\\\\\$|\/var\/|\/etc\/|\/usr\/)",
        # WordPress 특화 - 위험한 파일 접근
        r"WP_CONTENT_DIR\s*\.\s*[\"']\s*\.\s*\$[^;]+\s*\.\s*[\"'].*(?:\.\.\/|\\\\|\$_(?:GET|POST|REQUEST))"
    ],
    "RCE": [
        # 명령어 실행 - 변수가 명령어의 핵심 부분으로 사용되는 경우만
        r"(?:system|exec|shell_exec|passthru)\s*\(\s*(?:['\"].*[\"']\s*\.\s*)?(\$[^)]+)(?:\s*\.\s*['\"].*['\"])?\s*\)",
        # 백틱을 통한 명령어 실행
        r"`[^`]*(?:['\"].*[\"']\s*\.\s*)?(\$[^`]+)(?:\s*\.\s*['\"].*['\"])?[^`]*`",
        # 동적 함수 호출 - 변수가 함수명으로 직접 사용되는 경우만
        r"(?:call_user_func|create_function)\s*\(\s*['\"]?\s*\$[^,)]+\s*[,)]"
    ],
    "SSRF": [
        # URL 요청 - 외부 입력이 URL의 중요 부분에 사용되는 경우만
        r"curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*['\"]?\s*(?:https?:\/\/)?[^'\"]*\$[^'\"]*['\"]?\s*\)",
        r"file_get_contents\s*\(\s*['\"]?\s*(?:https?:\/\/)?[^'\"]*\$[^'\"]*['\"]?\s*\)",
        # WordPress 특화 - 안전하지 않은 HTTP 요청
        r"wp_remote_(?:get|post|request)\s*\(\s*['\"]?\s*(?:https?:\/\/)?[^'\"]*\$[^'\"]*['\"]?\s*[,)]"
    ]
}

# 안전한 함수 및 처리 패턴 - 더 엄격한 체크
SAFE_PATTERNS = {
    "SQLi": [
        # 완전한 Prepared Statement 체인
        r"\$stmt\s*=\s*\$[^;]+->prepare\s*\([^)]+\)\s*;\s*(?:\$stmt->bind_param\s*\([^)]+\)\s*;)*\s*\$stmt->execute\s*\(\s*\)",
        # WordPress의 안전한 prepare
        r"\$wpdb->prepare\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:\$[^,)]+\s*,?\s*)+\)",
        # 완전한 이스케이프 체인
        r"mysqli_real_escape_string\s*\([^,]+,\s*trim\s*\(\s*mysqli_real_escape_string\s*\([^,]+,\s*\$[^)]+\)\s*\)\)"
    ],
    "XSS": [
        # 완전한 이스케이프 체인
        r"esc_(?:html|attr|url|js)\s*\(\s*sanitize_text_field\s*\(\s*wp_strip_all_tags\s*\(\s*\$[^)]+\)\)\)",
        r"htmlspecialchars\s*\(\s*strip_tags\s*\(\s*trim\s*\(\s*\$[^)]+\)\)\s*,\s*ENT_QUOTES\)",
        # WordPress 안전한 출력
        r"wp_kses_post\s*\(\s*sanitize_text_field\s*\(\s*wp_strip_all_tags\s*\(\s*\$[^)]+\)\)\)",
        # JSON 안전한 인코딩
        r"json_encode\s*\([^,]+,\s*(?:JSON_HEX_TAG\s*\|\s*JSON_HEX_AMP\s*\|\s*JSON_HEX_APOS\s*\|\s*JSON_HEX_QUOT)\)"
    ],
    "LFI": [
        # 완전한 경로 검증 체인
        r"basename\s*\(\s*sanitize_file_name\s*\(\s*wp_strip_all_tags\s*\(\s*\$[^)]+\)\)\)",
        # 절대 경로 강제와 검증
        r"realpath\s*\(\s*WP_CONTENT_DIR\s*\.\s*DIRECTORY_SEPARATOR\s*\.\s*basename\s*\(\s*\$[^)]+\)\)",
        # 허용된 디렉토리 체크
        r"strpos\s*\(\s*realpath\s*\(\s*\$[^)]+\)\s*,\s*(?:WP_CONTENT_DIR|ABSPATH)\s*\)\s*===\s*0"
    ],
    "RCE": [
        # 완전한 명령어 이스케이프 체인
        r"escapeshellcmd\s*\(\s*escapeshellarg\s*\(\s*trim\s*\(\s*\$[^)]+\)\)\)",
        # 화이트리스트 기반 명령어 검증
        r"in_array\s*\(\s*trim\s*\(\s*\$[^)]+\)\s*,\s*array\s*\([^)]+\)\s*,\s*true\)"
    ],
    "SSRF": [
        # 완전한 URL 검증 체인
        r"wp_http_validate_url\s*\(\s*esc_url_raw\s*\(\s*wp_strip_all_tags\s*\(\s*\$[^)]+\)\)\)",
        # 도메인 화이트리스트 검증
        r"parse_url\s*\(\s*\$[^,)]+\s*,\s*PHP_URL_HOST\)\s*.*in_array\s*\([^,]+,\s*\$allowed_hosts\s*,\s*true\)"
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

def is_sanitized(line: str, vuln_type: str, code_lines: list, current_line: int) -> bool:
    """주어진 라인이 적절히 sanitize 되었는지 확인"""
    # 기본 sanitization 체크
    if any(pattern.search(line) for pattern in COMPILED_SAFE_PATTERNS.get(vuln_type, [])):
        return True
    
    # 컨텍스트별 추가 체크
    context_checks = {
        "SQLi": [
            # 완전한 prepared statement 사용
            (r"\$stmt\s*=\s*[^;]+->prepare", r"\$stmt->bind_param", r"\$stmt->execute"),
            # 화이트리스트 기반 검증
            (r"in_array\s*\(\s*\$[^,]+\s*,\s*array\s*\([^)]+\)\s*,\s*true\)", r"mysqli_real_escape_string")
        ],
        "XSS": [
            # 안전한 JSON 응답
            (r"header\s*\(\s*['\"]Content-Type:\s*application/json", r"json_encode\s*\([^,]+,\s*JSON_HEX"),
            # 숫자형 데이터 검증
            (r"is_numeric\s*\(\s*\$[^)]+\)", r"filter_var\s*\(\s*\$[^,]+,\s*FILTER_VALIDATE_(?:INT|FLOAT)")
        ],
        "LFI": [
            # 파일 확장자 화이트리스트
            (r"pathinfo\s*\(\s*\$[^,]+,\s*PATHINFO_EXTENSION\)", r"in_array\s*\([^,]+,\s*array\s*\(['\"](?:jpg|png|gif|pdf)['\"]\)\s*,\s*true\)"),
            # 절대 경로 검증
            (r"realpath\s*\(\s*\$[^)]+\)", r"strpos\s*\([^,]+,\s*(?:WP_CONTENT_DIR|ABSPATH)\)\s*===\s*0")
        ]
    }
    
    # 컨텍스트별 체크 실행
    if vuln_type in context_checks:
        # 현재 라인 주변 5줄 검사 (위아래로 각각 5줄)
        start = max(0, current_line - 5)
        end = min(len(code_lines), current_line + 5)
        context = "\n".join(code_lines[start:end])
        
        for patterns in context_checks[vuln_type]:
            if all(re.search(pattern, context, re.IGNORECASE) for pattern in patterns):
                return True
    
    return False

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

    # 각 취약점 유형별 검사
    for i, line in enumerate(code_lines):
        # CSRF 컨텍스트 추적
        if '<form' in line.lower():
            in_form = True
            form_start_line = i
            method_match = re.search(r'method=["\'](\w+)["\']', line.lower())
            form_method = method_match.group(1) if method_match else "get"
            
            # AJAX form이나 API endpoint, admin 페이지는 제외
            if 'data-ajax' in line or 'api-endpoint' in line or 'wp-admin' in line:
                in_form = False
                continue

        # CSRF 토큰 체크 - 더 엄격한 기준 적용
        if in_form:
            csrf_patterns = [
                # WordPress nonce
                r'wp_nonce_field\s*\(\s*[^)]+\)',
                r'wp_create_nonce\s*\(\s*[^)]+\)',
                # 일반적인 CSRF 토큰
                r'<input[^>]+(?:csrf|nonce)[^>]+>',
                # AJAX nonce
                r'var\s+[a-zA-Z_]+nonce\s*=\s*["\'][^"\']+["\']',
                # 세션 기반 토큰
                r'<input[^>]+value=["\']<?php\s+echo\s+session_id\(\)'
            ]
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in csrf_patterns):
                has_csrf_token = True

        if '</form>' in line.lower():
            if form_method.lower() == "post" and not has_csrf_token:
                # API endpoint, AJAX form, admin 페이지가 아닌 경우만 보고
                context = "\n".join(code_lines[max(0, form_start_line-5):form_start_line+5])
                if not any(('api' in context.lower() or 'ajax' in context.lower() or 'wp-admin' in context.lower())):
                    vuln_results["CSRF"].append({
                        'line': form_start_line + 1,
                        'code': code_lines[form_start_line].strip(),
                        'description': 'POST form without CSRF protection'
                    })
            in_form = False
            has_csrf_token = False
            form_start_line = -1

        # 다른 취약점 검사 - 컨텍스트 기반 필터링 추가
        for vuln_type, patterns in COMPILED_PATTERNS.items():
            if vuln_type == "CSRF":
                continue
            
            for pattern in patterns:
                if pattern.search(line):
                    for var_name, var_info in tainted_vars.items():
                        if f'${var_name}' in line:
                            # 컨텍스트 기반 필터링
                            if not is_sanitized(line, vuln_type, code_lines, i):
                                # 추가 컨텍스트 체크
                                should_report = True
                                
                                # 각 취약점 유형별 추가 검증
                                if vuln_type == "SQLi":
                                    # SELECT 문에서 안전한 컨텍스트 체크
                                    if re.search(r"SELECT\s+COUNT\s*\(\s*\*\s*\)", line, re.IGNORECASE):
                                        should_report = False
                                
                                elif vuln_type == "XSS":
                                    # 이미 이스케이프된 컨텍스트 체크
                                    if re.search(r"htmlspecialchars\s*\(\s*\$" + var_name, "\n".join(code_lines[max(0, i-3):i])):
                                        should_report = False
                                
                                elif vuln_type == "LFI":
                                    # 안전한 디렉토리 체크
                                    if re.search(r"strpos\s*\(\s*\$" + var_name + r"\s*,\s*(?:WP_CONTENT_DIR|ABSPATH)", line):
                                        should_report = False
                                
                                elif vuln_type == "RCE":
                                    # 화이트리스트 기반 명령어 체크
                                    if re.search(r"in_array\s*\(\s*\$" + var_name + r"\s*,\s*\$allowed_commands", "\n".join(code_lines[max(0, i-3):i])):
                                        should_report = False
                                
                                elif vuln_type == "SSRF":
                                    # 허용된 도메인 체크
                                    if re.search(r"parse_url\s*\(\s*\$" + var_name + r".*\$allowed_hosts", "\n".join(code_lines[max(0, i-3):i])):
                                        should_report = False
                                
                                if should_report:
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