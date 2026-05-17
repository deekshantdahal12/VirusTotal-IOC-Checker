# vt_checker.py

A command-line threat intelligence tool that queries the [VirusTotal API](https://www.virustotal.com/) to check IPs, file hashes, and domains against 90+ security vendors. Built for analysts and homelab defenders who want fast, no-noise IOC lookups without wading through VirusTotal's web UI.

---

## Features

| Feature | Details |
|---|---|
| **IP Lookup** | Detections, country, ASN, and risk verdict |
| **Hash Lookup** | MD5 / SHA-1 / SHA-256 — handles unknown hashes gracefully |
| **Domain Lookup** | Strips full URLs automatically, returns malicious/phishing flags |
| **Bulk File Mode** | Feed it a `.txt` file, it auto-detects each IOC type and routes it |
| **Rate Limiting** | 16s pause between bulk requests — won't get your key banned |
| **Clean Output** | No raw JSON. Just the signal. |

---

## Requirements

- Python 3.7+
- A free [VirusTotal API key](https://www.virustotal.com/gui/join-us)

Install dependencies:

```bash
pip install requests python-dotenv
```

---

## Setup

**1. Clone or download the script.**

**2. Create a `.env` file** in the same directory as the script:

```
VT_API_KEY=your_api_key_here
```

> Never hardcode your key in the script. This file should be in your `.gitignore` if you're pushing to GitHub.

**3. You're done.**

---

## Usage

### Check a single IP
```bash
python vt_checker.py ip 185.220.101.45
```
```
[*] Checking IP: 185.220.101.45
[+] 185.220.101.45
    Detections: 18/93 malicious, 3/93 suspicious
    Country:    DE
    ASN:        24940 (Hetzner Online GmbH)
    [!!!] HIGH RISK — block and isolate connected machines
```

---

### Check a file hash (MD5, SHA-1, or SHA-256)
```bash
python vt_checker.py hash d41d8cd98f00b204e9800998ecf8427e
```
```
[*] Checking hash: d41d8cd98f00b204e9800998ecf8427e
[+] evildoc.exe
    Type:        Win32 EXE
    Size:        52,736 bytes
    Detections:  43/72
    Family:      trojan.genericgb/androm
    First seen:  2023-11-02 14:32:01
    [!!!] CONFIRMED MALWARE
```

If the hash has never been submitted to VirusTotal:
```
[?] Unknown to VirusTotal — could be clean or never submitted
```

---

### Check a domain
Works with bare domains or full URLs — it strips the noise automatically.

```bash
python vt_checker.py domain malicious-site.ru
python vt_checker.py domain https://phishing-page.com/login/steal
```
```
[*] Checking domain: phishing-page.com
[+] phishing-page.com
    Detections:  12/89 malicious, 4/89 suspicious
    Registrar:   Namecheap, Inc.
    Categories:  phishing, malware
    [!!!] HIGH RISK — likely phishing/malware hosting
```

---

### Bulk check from a file

Create a `.txt` file with one IOC per line. Mix types freely — the script figures it out.

```
# Indicators from phishing email — 2025-05-14
185.220.101.45
d41d8cd98f00b204e9800998ecf8427e
suspicious-login-page.ru
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
```

> Lines starting with `#` are treated as comments and skipped.

```bash
python vt_checker.py file iocs.txt
```

The script will pause **16 seconds** between each request. On the free API tier (4 requests/minute), this lets you walk away and come back to results — no babysitting, no 429 errors.

---

## Risk Thresholds

The verdicts are opinionated but practical. Tune the numbers in the source if your threat tolerance differs.

| Verdict | Condition |
|---|---|
| `[!!!] HIGH RISK` | 5+ engines flag as malicious |
| `[!!] MEDIUM RISK` | 1–4 malicious, or 3+ suspicious |
| `[OK] Clean` | Zero detections |

---

## File Structure

```
.
├── vt_checker.py   # The script
├── .env            # Your API key — DO NOT commit this
├── .gitignore      # Should include .env
└── iocs.txt        # Optional: your bulk IOC list
```

**`.gitignore` minimum:**
```
.env
__pycache__/
```

---

## API Limits (Free Tier)

| Limit | Value |
|---|---|
| Requests per minute | 4 |
| Requests per day | 500 |
| Requests per month | 15,500 |

The built-in rate limiter handles the per-minute cap. For large bulk jobs, be mindful of the daily ceiling.

---

## License

MIT — do whatever you want, just don't blame me if a domain comes back clean and it isn't.
