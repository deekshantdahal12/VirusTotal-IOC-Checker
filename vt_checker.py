import os
import re
import sys
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY, "Accept": "application/json"}

RATE_LIMIT_DELAY = 16


def check_ip(ip):
    print(f"\n[*] Checking IP: {ip}")
    r = requests.get(f"{BASE_URL}/ip_addresses/{ip}", headers=HEADERS)

    if r.status_code != 200:
        print(f"[!] Error {r.status_code}")
        return

    attrs = r.json()["data"]["attributes"]
    stats = attrs["last_analysis_stats"]
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    print(f"[+] {ip}")
    print(f"    Detections: {malicious}/{total} malicious, {suspicious}/{total} suspicious")
    print(f"    Country:    {attrs.get('country', 'Unknown')}")
    print(f"    ASN:        {attrs.get('asn', 'N/A')} ({attrs.get('as_owner', 'Unknown')})")

    if malicious >= 5:
        print("    [!!!] HIGH RISK — block and isolate connected machines")
    elif malicious >= 1 or suspicious >= 3:
        print("    [!!] MEDIUM RISK — worth investigating connections")
    else:
        print("    [OK] Clean")


def check_hash(file_hash):
    print(f"\n[*] Checking hash: {file_hash}")
    r = requests.get(f"{BASE_URL}/files/{file_hash}", headers=HEADERS)

    if r.status_code == 404:
        print("    [?] Unknown to VirusTotal — could be clean or never submitted")
        return

    if r.status_code != 200:
        print(f"    [!] Error {r.status_code}")
        return

    attrs = r.json()["data"]["attributes"]
    stats = attrs["last_analysis_stats"]
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)

    print(f"[+] {attrs.get('meaningful_name', 'Unknown filename')}")
    print(f"    Type:        {attrs.get('type_description', 'Unknown')}")
    print(f"    Size:        {attrs.get('size', 0):,} bytes")
    print(f"    Detections:  {malicious}/{total}")

    if malicious > 0:
        label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "")
        if label:
            print(f"    Family:      {label}")

    first_seen = attrs.get("first_submission_date")
    if first_seen:
        print(f"    First seen:  {datetime.fromtimestamp(first_seen)}")

    if malicious >= 10:
        print("    [!!!] CONFIRMED MALWARE")
    elif malicious >= 3:
        print("    [!!] LIKELY MALWARE")
    elif malicious >= 1:
        print("    [!] Possible malware — dig deeper")
    else:
        print("    [OK] Clean")


def check_domain(raw):
    # Strip full URLs down to bare domain — people paste these all the time
    domain = re.sub(r"^https?://", "", raw).split("/")[0].strip()

    print(f"\n[*] Checking domain: {domain}")
    r = requests.get(f"{BASE_URL}/domains/{domain}", headers=HEADERS)

    if r.status_code != 200:
        print(f"    [!] Error {r.status_code}")
        return

    attrs = r.json()["data"]["attributes"]
    stats = attrs["last_analysis_stats"]
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    print(f"[+] {domain}")
    print(f"    Detections:  {malicious}/{total} malicious, {suspicious}/{total} suspicious")
    print(f"    Registrar:   {attrs.get('registrar', 'Unknown')}")

    cats = attrs.get("categories", {})
    if cats:
        # Category values vary by vendor, just grab the first couple
        labels = list(cats.values())[:2]
        print(f"    Categories:  {', '.join(labels)}")

    if malicious >= 5:
        print("    [!!!] HIGH RISK — likely phishing/malware hosting")
    elif malicious >= 1 or suspicious >= 3:
        print("    [!!] MEDIUM RISK — flagged by some vendors")
    else:
        print("    [OK] Clean")


def detect_and_check(ioc):
    # Hash lengths are fixed — easiest check first
    if len(ioc) in (32, 40, 64) and re.fullmatch(r"[a-fA-F0-9]+", ioc):
        check_hash(ioc)
        return

    # IPv4 pattern
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", ioc):
        check_ip(ioc)
        return

    # Anything with a dot and no pure-numeric structure is probably a domain
    if "." in ioc:
        check_domain(ioc)
        return

    print(f"[?] Can't figure out what this is: {ioc}")


def bulk_check(filename):
    print(f"[*] Loading IOCs from: {filename}")

    with open(filename) as f:
        iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"[*] {len(iocs)} IOCs found\n")

    for i, ioc in enumerate(iocs):
        detect_and_check(ioc)
        print("-" * 50)

        # Skip the delay after the last one — no request follows it
        if i < len(iocs) - 1:
            print(f"    [~] Waiting {RATE_LIMIT_DELAY}s (rate limit)...")
            time.sleep(RATE_LIMIT_DELAY)


if __name__ == "__main__":
    if len(sys.argv) < 3 and (len(sys.argv) < 2 or sys.argv[1] != "file"):
        print("Usage:")
        print("  python vt_checker.py ip <address>")
        print("  python vt_checker.py hash <md5|sha1|sha256>")
        print("  python vt_checker.py domain <domain or url>")
        print("  python vt_checker.py file <iocs.txt>")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "ip":
        check_ip(sys.argv[2])
    elif mode == "hash":
        check_hash(sys.argv[2])
    elif mode == "domain":
        check_domain(sys.argv[2])
    elif mode == "file":
        bulk_check(sys.argv[2])
    else:
        print(f"[!] Unknown mode: {mode}")
        sys.exit(1)