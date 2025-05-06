import argparse, requests, urllib.parse, threading, time, os
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style

init(autoreset=True)
results = []

BANNER = f"""{Fore.MAGENTA}{Style.BRIGHT}
 .---..        .    --.--.   .    .        .-.  .--.    .    .   .
 |    |       / \     |  |\  |   / \      (   ):       / \   |\  |
 |--- |      /___\    |  | \ |  /___\      `-. |      /___\  | \ |
 |    |     /     \   |  |  \| /     \    (   ):     /     \ |  \|
 '---''---''       `--'--'   ''       `____`-'  `--''       `'   '.
             {Fore.CYAN}<< ELAINA_SCAN :: tool Pentest Scanner >>
"""

def print_result(msg, level="info"):
    color = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "warn": Fore.YELLOW,
        "error": Fore.RED
    }.get(level, Fore.WHITE)
    print(f"{color}[{level.upper()}] {msg}")

def parse_args():
    parser = argparse.ArgumentParser(description="ELAINA_SCAN Framework")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--mode", required=True, help="Scan mode (sqli, xss, ssti, ssrf, lfi, redirect)")
    parser.add_argument("--payload", required=True, help="Payload file path")
    parser.add_argument("-p", "--proxy", help="Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    return parser.parse_args()

def build_url(url, param, payload):
    parsed = list(urllib.parse.urlparse(url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    query[param] = payload
    parsed[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed)

def send_request(url, proxy=None):
    try:
        r = requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=10, verify=False)
        return r
    except:
        return None

def scan_param(url, param, payloads, mode, proxy=None):
    for payload in payloads:
        full_url = build_url(url, param, payload)
        r = send_request(full_url, proxy)
        if not r:
            print_result(f"Timeout on {full_url}", "error")
            continue

        if mode == "sqli" and "sql" in r.text.lower():
            print_result(f"SQLi Detected! {full_url}", "success")
            results.append({"mode": "sqli", "url": full_url, "payload": payload, "vulnerable": True})
        elif mode == "xss" and payload.lower() in r.text.lower():
            print_result(f"XSS Detected! {full_url}", "success")
            results.append({"mode": "xss", "url": full_url, "payload": payload, "vulnerable": True})
        elif mode == "ssti" and "49" in r.text:
            print_result(f"SSTI Detected! {full_url}", "success")
            results.append({"mode": "ssti", "url": full_url, "payload": payload, "vulnerable": True})
        elif mode == "ssrf" and "127.0.0.1" in r.text:
            print_result(f"SSRF Suspected! {full_url}", "warn")
        elif mode == "lfi" and "root:x" in r.text:
            print_result(f"LFI Confirmed! {full_url}", "success")
        elif mode == "redirect" and r.is_redirect:
            print_result(f"Redirect Found! {full_url}", "warn")

def run_scan(url, mode, payload_file, threads, proxy=None):
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params:
        print_result("No parameters found in URL", "error")
        return

    with open(payload_file) as f:
        payloads = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for param in params:
            executor.submit(scan_param, url, param, payloads, mode, proxy)

if __name__ == "__main__":
    print(BANNER)
    args = parse_args()
    run_scan(args.url, args.mode, args.payload, args.threads, args.proxy)
