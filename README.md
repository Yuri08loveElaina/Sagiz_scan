# Sagiz_scan

Welcome to **Sagiz_scan**, a powerful and efficient scanning tool designed to simplify and enhance your scanning tasks.

## 🚀 Features

- Fast and accurate scanning capabilities
- User-friendly interface for easy operation
- Supports multiple file formats and options
- Designed for both beginners and advanced users

## Using ## 
- curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest 
- grep "browser_download_url.*nuclei-linux-amd64" \
- cut -d '"' -f 4 \
- wget -qi -
- chmod +x nuclei-linux-amd64
- sudo mv nuclei-linux-amd64 /usr/local/bin/nuclei
- git clone https://github.com/Dragontv1234/Sagiz_scan.git
- cd Sagiz_scan
- chmod +x ELAINA_SCAN.py
## How To Using Tools ## 
## ELAINA_SCAN.py ##
- python ELAINA_SCAN.py -u "http://target.com/page.php?id=1" -m sql -payload payloads/sql.txt --fuzz-params -proxy http://127.0.0.1:8080
   ## Elaina3.py ##
- python Elaina3.py -u "http://target.com/page.php?id=1" -m sqli --payload payloads/sqli.txt -p http://127.0.0.1:8080 -t 10
  python scanner.py -u "http://example.com/page.php?id=1" -m sql -payload payloads/sql.txt
Quét XSS: python scanner.py -u "http://example.com/search.php?q=test" -m xss -payload payloads/xss.txt
Kiểm tra CSRF: python scanner.py -u "http://example.com/form.php" -m csrf
Quét với Nuclei:
python scanner.py -u "http://example.com" -m nuclei
Thực hiện brute-force đăng nhập:
python scanner.py -u "http://example.com/login.php" -m bruteforce -userlist users.txt -passlist passwords.txtKhai thác RCE:python scanner.py -u "http://example.com/vulnerable.php?cmd=" -m exploit --exploit rce --cmd "whoami"
Khai thác LFI:python scanner.py -u "http://example.com/vulnerable.php?file=" -m exploit --exploit lfi --file "/etc/passwd"
Chạy toàn bộ quétpython scanner.py -u "http://example.com" -m fullscan -payload payloads/all.txt

## Develop By YURI08 ##
