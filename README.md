# 🔍 Web Vulnerability Scanner

A Python-based CLI tool to detect basic web vulnerabilities such as **Cross-Site Scripting (XSS)** and **SQL Injection (SQLi)** through automated form analysis and payload injection.

---

## 🚀 Features

* 🔎 Detects and extracts HTML forms from web pages
* 🧪 Performs **multi-payload testing** for XSS and SQL Injection
* ⚡ Simulates real-world attack vectors via form submission
* 📊 Generates **timestamped JSON reports**
* 🖥️ CLI-based execution for fast and simple usage

---

## 🛠️ Tech Stack

* Python
* requests
* BeautifulSoup

---

## ▶️ How to Run

1. Clone the repository:

```bash
git clone https://github.com/BeingGuru7/web-vuln-scanner.git
cd web-vuln-scanner
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the scanner:

```bash
python scanner.py https://httpbin.org/forms/post
```

---

## 📌 Sample Output

```text
==============================
   Web Vulnerability Scanner
==============================

[+] Target: https://httpbin.org/forms/post
[+] Scan started at: 2026-03-29 07:06:22
[+] Forms detected: 1

[+] Scanning Form #1
    [-] XSS not detected
    [-] SQL Injection not detected
----------------------------------------

========== Scan Summary ==========
Target: https://httpbin.org/forms/post
Forms scanned: 1
XSS vulnerabilities: 0
SQL Injection vulnerabilities: 0
Scan duration: 12.51 seconds
=================================

[+] Report saved as report_20260329_070622.json
```

---

## 📄 Report Format

```json
{
    "url": "https://example.com",
    "forms_scanned": 1,
    "xss_found": 0,
    "sqli_found": 0,
    "results": [
        {
            "form_id": 1,
            "action": "/post",
            "method": "post",
            "xss": false,
            "sqli": false
        }
    ]
}
```

---

## ⚠️ Limitations

* Detects only **basic reflected XSS**
* SQL Injection detection is **error-based only**
* Does not support:

  * DOM-based XSS
  * Stored XSS
  * Authentication-required pages
  * Multi-page crawling

---

## 📌 Disclaimer

This tool is developed for **educational purposes only**.
Do **not** use it on websites without proper authorization.

---

## 👤 Author

Guru Prasath V
GitHub: https://github.com/BeingGuru7
