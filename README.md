

# Passive Reconnaissance Tool

## Overview
This Python-based passive reconnaissance tool automates information gathering on a target domain. It retrieves technology details, IP information, subdomains, hidden directories, Google Dorks queries, user information, hidden links, and potential vulnerabilities like CRLF injection.

## Features
- **Technology Detection**: Identifies the technologies used by the target website using WhatsRun API.
- **IP & Geolocation Lookup**: Fetches IP information and location data using IPInfo API.
- **Subdomain Enumeration**: Uses `subfinder` to discover subdomains.
- **Directory Bruteforce**: Runs `dirsearch` to find hidden directories.
- **Google Dorks Queries**: Generates Google Dorks for potential security vulnerabilities.
- **User Information Extraction**: Extracts email addresses from the website.
- **Hidden Links Detection**: Uses `katana` for fast discovery of hidden links.
- **CRLF Injection Detection**: Checks for CRLF vulnerabilities in the target.

## Installation
Ensure you have the required tools installed:
```bash
pip install requests beautifulsoup4
sudo apt install subfinder dirsearch katana
```

## Usage
Run the script and provide a target domain:
```bash
python passive_recon.py
```
Then enter the domain when prompted.

## Disclaimer
This tool is intended for educational and security research purposes only. Ensure you have permission before testing any domain.

---

