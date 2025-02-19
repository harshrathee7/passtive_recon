import requests
import socket
import subprocess
import re
from bs4 import BeautifulSoup

def get_technologies(domain):
    """Identify technologies used by the website."""
    try:
        response = requests.get(f'https://whatsrun.net/api/v1/lookup?url={domain}')
        if response.status_code == 403:
            return "Forbidden: Check API key permissions for WhatsRun."
        return response.json()
    except Exception as e:
        return f"Error fetching technologies: {e}"

def get_ip_info(domain):
    """Get IP and geolocation information."""
    try:
        ip_address = socket.gethostbyname(domain)
        api_key = "YOUR_IPINFO_API_KEY"
        headers = {"Authorization": f"Bearer {api_key}"} if api_key != "YOUR_IPINFO_API_KEY" else {}
        response = requests.get(f'https://ipinfo.io/{ip_address}/json', headers=headers)
        if response.status_code == 403:
            return "Error: Invalid or missing IPInfo API key. Visit https://ipinfo.io/signup to get a key."
        return response.json()
    except Exception as e:
        return f"Error fetching IP info: {e}"

def find_subdomains(domain):
    """Find subdomains using subfinder."""
    try:
        result = subprocess.run(['subfinder', '-d', domain], capture_output=True, text=True)
        return "\n".join(result.stdout.strip().split('\n')) if result.stdout.strip() else "No subdomains found."
    except Exception as e:
        return f"Error fetching subdomains: {e}"

def run_dirsearch(domain):
    """Run dirsearch to find hidden directories."""
    try:
        result = subprocess.run(['dirsearch', '-u', f'http://{domain}', '-e', 'php,html,js'], capture_output=True, text=True)
        return "\n".join(result.stdout.strip().split('\n')) if result.stdout.strip() else "No directories found."
    except Exception as e:
        return f"Error running dirsearch: {e}"

def google_dorks(domain):
    """Use Google Dorks to find sensitive information."""
    dorks = [
        f"site:{domain} intitle:index of",
        f"site:{domain} ext:sql | ext:txt | ext:log",
        f"site:{domain} inurl:admin",
        f"site:{domain} \"password\"",
    ]
    return "\n".join(dorks)

def extract_user_info(domain):
    """Extract user information from metadata."""
    try:
        response = requests.get(f'http://{domain}')
        soup = BeautifulSoup(response.text, 'html.parser')
        emails = set(re.findall(r'[\w\.-]+@[\w\.-]+', soup.text))
        return "\n".join(emails) if emails else "No emails found."
    except Exception as e:
        return f"Error extracting user info: {e}"

def find_hidden_links(domain):
    """Find hidden links using Katana with increased speed."""
    try:
        result = subprocess.run(['katana', '-u', f'http://{domain}', '--concurrency', '10', '--depth', '3'], capture_output=True, text=True)
        return "\n".join(result.stdout.strip().split('\n')) if result.stdout.strip() else "No hidden links found."
    except Exception as e:
        return f"Error finding hidden links: {e}"

def check_crlf_vuln(domain):
    """Check for CRLF injection vulnerability."""
    try:
        payload = "%0d%0aSet-Cookie:crlf=injection"
        url = f"http://{domain}/%E5%98%8A%E5%98%8D?{payload}"
        response = requests.get(url, allow_redirects=False)
        if "crlf=injection" in response.headers.get("Set-Cookie", ""):
            return "CRLF Injection vulnerability detected!"
        return "No CRLF vulnerability detected."
    except Exception as e:
        return f"Error checking CRLF vulnerability: {e}"

def main():
    domain = input("Enter target domain: ")
    print("Fetching technologies...\n", get_technologies(domain), "\n")
    print("Fetching IP information...\n", get_ip_info(domain), "\n")
    print("Finding subdomains...\n", find_subdomains(domain), "\n")
    print("Running directory search...\n", run_dirsearch(domain), "\n")
    print("Generating Google Dorks queries...\n", google_dorks(domain), "\n")
    print("Extracting user information...\n", extract_user_info(domain), "\n")
    print("Finding hidden links...\n", find_hidden_links(domain), "\n")
    print("Checking for CRLF vulnerability...\n", check_crlf_vuln(domain), "\n")

if __name__ == "__main__":
    main()
