curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest
grep "browser_download_url.*nuclei-linux-amd64" \
cut -d '"' -f 4 \
wget -qi -
chmod +x nuclei-linux-amd64
sudo mv nuclei-linux-amd64 /usr/local/bin/nuclei
git clone https://github.com/Dragontv1234/Sagiz_scan.git
cd Sagiz_scan
chmod +x ELAINA_SCAN.py
