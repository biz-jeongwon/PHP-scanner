# 🛡️ PHP Vulnerability Scanner

A powerful static analysis tool for scanning **WordPress plugins** to detect common PHP security vulnerabilities such as **SQL Injection**, **XSS**, **LFI**, **RCE**, **SSRF**, and **CSRF**.

---

## 📦 Environment Setup

Install required Python packages:

```bash
pip install -r requirements.txt
```

---

## 🔍 WordPress Plugin Scanning Workflow

### 📥 1. Download WordPress Plugins

```bash
python3 wp-downloader.py
```

- **Instructions:**
  - Enter keywords separated by spaces (e.g., `seo security backup`)
  - Enter start and end page numbers

---

### 🧪 2. Scan Plugins for Vulnerabilities

```bash
python3 scanner.py
```

#### ✅ Example Output

```plaintext
██████╗ ██╗  ██╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔══██╗██║  ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝███████║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██╔══██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║  ██║██║         ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

[+] Progress: 100% (10245/10245)
[+] Scan Complete.
[+] Vulnerable files detected: 66
[+] Results saved to scan_result.json

[+] Vulnerability Summary:
    [+] SQLi: 0
    [+] XSS: 103
    [+] LFI: 0
    [+] RCE: 0
    [+] SSRF: 9
    [+] CSRF: 3
```

---

### 📊 3. Generate Detailed Report

```bash
python3 generate_report.py
```

![Report Example](report_example.png)

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 📄 License

This project is licensed under the MIT License.