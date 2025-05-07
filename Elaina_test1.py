import argparse
import logging
import os
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict

import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

BANNER = r"""
 
                    _               _              _                    _              _                   _                                       _                  _               _                   _
        /\ \            _\ \           / /\                 /\ \           /\ \     _          / /\                                    / /\              /\ \             / /\                /\ \     _
       /  \ \          /\__ \         / /  \                \ \ \         /  \ \   /\_\       / /  \                                  / /  \            /  \ \           / /  \              /  \ \   /\_\
      / /\ \ \        / /_ \_\       / / /\ \               /\ \_\       / /\ \ \_/ / /      / / /\ \                                / / /\ \__        / /\ \ \         / / /\ \            / /\ \ \_/ / /
     / / /\ \_\      / / /\/_/      / / /\ \ \             / /\/_/      / / /\ \___/ /      / / /\ \ \                              / / /\ \___\      / / /\ \ \       / / /\ \ \          / / /\ \___/ /
    / /_/_ \/_/     / / /          / / /  \ \ \           / / /        / / /  \/____/      / / /  \ \ \                             \ \ \ \/___/     / / /  \ \_\     / / /  \ \ \        / / /  \/____/
   / /____/\       / / /          / / /___/ /\ \         / / /        / / /    / / /      / / /___/ /\ \                             \ \ \          / / /    \/_/    / / /___/ /\ \      / / /    / / /
  / /\____\/      / / / ____     / / /_____/ /\ \       / / /        / / /    / / /      / / /_____/ /\ \         ___________    _    \ \ \        / / /            / / /_____/ /\ \    / / /    / / /
 / / /______     / /_/_/ ___/\  / /_________/\ \ \  ___/ / /__      / / /    / / /      / /_________/\ \ \    ___/__________/\  /_/\__/ / /       / / /________    / /_________/\ \ \  / / /    / / /
/ / /_______\   /_______/\__\/ / / /_       __\ \_\/\__\/_/___\    / / /    / / /      / / /_       __\ \_\  /__________    \ \ \ \/___/ /       / / /_________\  / / /_       __\ \_\/ / /    / / /
\/__________/   \_______\/     \_\___\     /____/_/\/_________/    \/_/     \/_/       \_\___\     /____/_/  \____\/    \____\/  \_____\/        \/____________/  \_\___\     /____/_/\/_/     \/_/

              ELAINA_SCAN 2.0 super scan - Pentest Framework
"""

print(BANNER)

# Thread-safe results container
results = []

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='ELAINA_SCAN 2.0 - Pentest Framework')
    parser.add_argument('-u', '--url', required=True,
                        help='Target URL with parameters (e.g., http://example.com/page.php?id=1)')
    parser.add_argument('-m', '--mode', required=True,
                        choices=['sqli', 'xss', 'ssti', 'ssrf', 'lfi', 'redirect'],
                        help='Scan mode')
    parser.add_argument('-p', '--proxy', default=None,
                        help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--payload', required=True,
                        help='File path to payload list')
    parser.add_argument('-t', '--threads', type=int, default=5,
                        help='Number of concurrent threads (default: 5)')
    return parser.parse_args()

def build_url(url: str, param: str, payload: str) -> str:
    parsed_url = urllib.parse.urlparse(url)
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
    query_params[param] = payload
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    rebuilt_url = parsed_url._replace(query=new_query)
    return urllib.parse.urlunparse(rebuilt_url)

def send_request(url: str, proxy: Optional[str] = None, timeout: int = 10) -> Optional[requests.Response]:
    session = requests.Session()
    if proxy:
        session.proxies.update({'http': proxy, 'https': proxy})
    try:
        response = session.get(url, timeout=timeout)
        return response
    except requests.RequestException as e:
        logging.debug(f"Request failed for {url}: {str(e)}")
        return None

def check_delay(url: str, proxy: Optional[str], threshold: float = 4.5) -> bool:
    start_time = time.time()
    response = send_request(url, proxy)
    if response:
        elapsed = time.time() - start_time
        return elapsed > threshold
    return False

def is_reflected(response_text: str, payload: str) -> bool:
    return payload.lower() in response_text.lower()

def scan_payload(url: str, param: str, payload: str, mode: str, proxy: Optional[str]) -> None:
    target_url = build_url(url, param, payload)
    response = send_request(target_url, proxy)
    if not response:
        return

    vulnerable = False

    if mode == 'sqli':
        error_signatures = ['sql syntax', 'mysql', 'syntax error', 'unclosed quotation', 'odbc', 'sqlstate']
        if any(err in response.text.lower() for err in error_signatures):
            logging.info(f"[SQLi] Vulnerability detected at {target_url}")
            vulnerable = True
        elif 'sleep' in payload.lower() and check_delay(target_url, proxy):
            logging.info(f"[SQLi] Blind SQLi detected at {target_url}")
            vulnerable = True

    elif mode == 'xss':
        if is_reflected(response.text, payload):
            logging.info(f"[XSS] Reflection detected at {target_url}")
            vulnerable = True

    elif mode == 'ssti':
        ssti_indicators = ['49', 'syntaxerror', 'templateerror', 'traceback']
        if any(indicator in response.text.lower() for indicator in ssti_indicators):
            logging.info(f"[SSTI] Possible SSTI at {target_url}")
            vulnerable = True

    elif mode == 'ssrf':
        ssrf_indicators = ['localhost', '127.0.0.1', 'internal server error', 'connection refused']
        if any(indicator in response.text.lower() for indicator in ssrf_indicators):
            logging.info(f"[SSRF] Possible SSRF at {target_url}")
            vulnerable = True

    elif mode == 'lfi':
        if 'root:x' in response.text.lower() or 'no such file or directory' not in response.text.lower():
            logging.info(f"[LFI] Possible LFI at {target_url}")
            vulnerable = True

    elif mode == 'redirect':
        if response.is_redirect or response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get('Location', '')
            original_netloc = urllib.parse.urlparse(url).netloc
            redirect_netloc = urllib.parse.urlparse(location).netloc
            if redirect_netloc and redirect_netloc != original_netloc:
                logging.info(f"[Redirect] Open redirect at {target_url} -> {location}")
                vulnerable = True

    if vulnerable:
        results.append({
            'mode': mode,
            'url': target_url,
            'payload': payload
        })

def main() -> None:
    args = parse_args()

    parsed_url = urllib.parse.urlparse(args.url)
    params = dict(urllib.parse.parse_qsl(parsed_url.query))
    if not params:
        logging.error("[-] No query parameters found in the URL. Exiting.")
        sys.exit(1)

    if not os.path.isfile(args.payload):
        logging.error(f"[-] Payload file not found: {args.payload}")
        sys.exit(1)

    with open(args.payload, 'r', encoding='utf-8') as f:
        payloads = [line.strip() for line in f if line.strip()]

    logging.info(f"[+] Starting scan on {args.url} with mode {args.mode}")
    logging.info(f"[+] Using {args.threads} threads and proxy: {args.proxy}")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for param in params:
            for payload in payloads:
                futures.append(executor.submit(scan_payload, args.url, param, payload, args.mode, args.proxy))

        # Optionally, wait for all futures and handle exceptions if needed
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error during scanning task: {str(e)}")

    # Summary report
    print("\n[+] Scan completed.")
    if results:
        print(f"[+] Vulnerabilities found: {len(results)}")
        for record in results:
            print(f"Mode: {record['mode']}, URL: {record['url']}, Payload: {record['payload']}")
    else:
        print("[-] No vulnerabilities found.")

if __name__ == '__main__':
    main()
