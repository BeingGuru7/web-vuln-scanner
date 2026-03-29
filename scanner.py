import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
import sys
from datetime import datetime


def get_forms(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    details = {}

    details["action"] = form.attrs.get("action")
    details["method"] = form.attrs.get("method", "get").lower()

    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")

        if input_name:
            inputs.append({
                "type": input_type,
                "name": input_name
            })

    details["inputs"] = inputs
    return details


def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input in form_details["inputs"]:
        if input["type"] in ["text", "search", "email"]:
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=5)
        else:
            return requests.get(target_url, params=data, timeout=5)
    except requests.exceptions.RequestException:
        return None


# -------- XSS Detection --------
def is_xss_vulnerable(response, payload):
    if not response:
        return False

    if "text/html" not in response.headers.get("Content-Type", ""):
        return False

    soup = BeautifulSoup(response.text, "html.parser")

    for script in soup.find_all("script"):
        if payload in script.text:
            return True

    return False


# -------- SQL Injection Detection --------
def is_sqli_vulnerable(response):
    if not response:
        return False

    errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sql syntax error"
    ]

    response_text = response.text.lower()

    for error in errors:
        if error in response_text:
            return True

    return False


def scan(url):
    start_time = datetime.now()

    forms = get_forms(url)

    print("\n==============================")
    print("   Web Vulnerability Scanner")
    print("==============================\n")

    print(f"[+] Target: {url}")
    print(f"[+] Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[+] Forms detected: {len(forms)}\n")

    results = []
    total_xss = 0
    total_sqli = 0

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "'\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ]

    sqli_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1"
    ]

    for i, form in enumerate(forms, start=1):
        details = get_form_details(form)

        print(f"[+] Scanning Form #{i}")

        form_result = {
            "form_id": i,
            "action": details["action"],
            "method": details["method"],
            "xss": False,
            "sqli": False
        }

        # -------- XSS --------
        for payload in xss_payloads:
            response = submit_form(details, url, payload)

            if is_xss_vulnerable(response, payload):
                print("    [!!!] XSS detected")
                form_result["xss"] = True
                total_xss += 1
                break
        else:
            print("    [-] XSS not detected")

        # -------- SQLi --------
        for payload in sqli_payloads:
            response = submit_form(details, url, payload)

            if is_sqli_vulnerable(response):
                print("    [!!!] SQL Injection detected")
                form_result["sqli"] = True
                total_sqli += 1
                break
        else:
            print("    [-] SQL Injection not detected")

        print("-" * 40)

        results.append(form_result)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # -------- Summary --------
    print("\n========== Scan Summary ==========")
    print(f"Target: {url}")
    print(f"Forms scanned: {len(forms)}")
    print(f"XSS vulnerabilities: {total_xss}")
    print(f"SQL Injection vulnerabilities: {total_sqli}")
    print(f"Scan duration: {duration:.2f} seconds")
    print("=================================\n")

    # -------- Save report with timestamp --------
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.json"

    report = {
        "url": url,
        "scan_started": start_time.strftime('%Y-%m-%d %H:%M:%S'),
        "scan_ended": end_time.strftime('%Y-%m-%d %H:%M:%S'),
        "duration_seconds": duration,
        "forms_scanned": len(forms),
        "xss_found": total_xss,
        "sqli_found": total_sqli,
        "results": results
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"[+] Report saved as {filename}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("Enter URL: ")

    scan(target_url)