import argparse
import requests
import urllib.parse
import threading
import time
import sys
import os
import re
from concurrent.futures import ThreadPoolExecutor

# ASCII banner
BANNER = r"""
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ 
            ||E |||L |||A |||I |||N |||A |||_ |||S |||C |||A |||N ||
            ||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||
            |/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|

                    coding by YURI08     - Pentest Framework
"""

print(BANNER)

# Global results list
results = []

# Function to parse arguments
def parse_args():
    parser = argparse.ArgumentParser(description='ELAINA_SCAN - Pentest Framework')
    parser.add_argument('-u', '--url', help='Target URL with parameters (e.g., http://example.com/page.php?id=1)', required=True)
    parser.add_argument('-m', '--mode', help='Scan mode: sqli, xss, ssti, ssrf, lfi, redirect', required=True)
    parser.add_argument('-p', '--proxy', help='Proxy (e.g., http://127.0.0.1:8080)', default=None)
    parser.add_argument('--payload', help='Payload file path', required=True)
    parser.add_argument('-t', '--threads', help='Number of threads (default: 5)', type=int, default=5)
    return parser.parse_args()

# Function to build URL with injected payload
def build_url(url, param, payload):
    parsed = list(urllib.parse.urlparse(url))
    query = dict(urllib.parse.parse_qsl(parsed[4]))
    query[param] = payload
    parsed[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(parsed)

# Function to infer parameter type
def infer_param_type(value):
    if value.isdigit():
        return 'int'
    elif value.lower() in ['true', 'false']:
        return 'bool'
    elif '/' in value:
        return 'path'
    else:
        return 'str'

# Function to check if payload is reflected in response
def is_reflected(response_text, payload):
    return payload.lower() in response_text.lower()

# Function to send HTTP request
def send_request(url, proxy):
    try:
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        response = requests.get(url, proxies=proxies, timeout=10)
        return response
    except requests.RequestException:
        return None

# Function to check for delay in response
def check_delay(url, proxy, threshold=4.5):
    start = time.time()
    response = send_request(url, proxy)
    if response and (time.time() - start) > threshold:
        return True
    return False

# Function to scan for vulnerabilities
def scan_payload(url, param, payload, mode, proxy):
    target_url = build_url(url, param, payload)
    response = send_request(target_url, proxy)
    if not response:
        return

    result = {'mode': mode, 'url': target_url, 'payload': payload, 'vulnerable': False}

    if mode == 'sqli':
        errors = ['sql syntax', 'mysql', 'syntax error', 'unclosed quotation', 'odbc']
        if any(error in response.text.lower() for error in errors):
            print(f"[SQLi] Vulnerability detected at {target_url}")
            result['vulnerable'] = True
        elif 'sleep' in payload.lower() and check_delay(target_url, proxy):
            print(f"[SQLi] Blind SQLi detected at {target_url}")
            result['vulnerable'] = True

    elif mode == 'xss':
        if is_reflected(response.text, payload):
            print(f"[XSS] Reflection detected at {target_url}")
            result['vulnerable'] = True

    elif mode == 'ssti':
        if '49' in response.text:
            print(f"[SSTI] Possible SSTI at {target_url}")
            result['vulnerable'] = True

    elif mode == 'ssrf':
        indicators = ['localhost', '127.0.0.1', 'internal server error']
        if any(indicator in response.text.lower() for indicator in indicators):
            print(f"[SSRF] Possible SSRF at {target_url}")
            result['vulnerable'] = True

    elif mode == 'lfi':
        if 'root:x' in response.text or 'No such file or directory' not in response.text:
            print(f"[LFI] Possible LFI at {target_url}")
            result['vulnerable'] = True

    elif mode == 'redirect':
        if response.is_redirect:
            location = response.headers.get('Location', '')
            if 'http' in location and not urllib.parse.urlparse(location).netloc.endswith(urllib.parse.urlparse(url).netloc):
                print(f"[Redirect] Open redirect at {target_url}")
                result['vulnerable'] = True

    if result['vulnerable']:
        results.append(result)

# Main function
def main():
    args = parse_args()
    parsed_url = urllib.parse.urlparse(args.url)
    params = dict(urllib.parse.parse_qsl(parsed_url.query))
    if not params:
        print("[-] No parameters found in URL.")
        sys.exit(1)

    # Load payloads
    if not os.path.isfile(args.payload):
        print(f"[-] Payload file not found: {args.payload}")
        sys.exit(1)

    with open(args.payload, 'r') as f:
        payloads = [line.strip() for line in f if line.strip()]

    # Start scanning
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for param in params:
            for payload in payloads:
                executor.submit(scan_payload, args.url, param, payload, args.mode, args.proxy)

    # Summary
    print("\n[+] Scan completed.")
    if results:
        print(f"[+] Vulnerabilities found: {len(results)}")
        for res in results:
            print(f"Mode: {res['mode']}, URL: {res['url']}, Payload: {res['payload']}")
    else:
        print("[-] No vulnerabilities found.")

if __name__ == '__main__':
    main()
