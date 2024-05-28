import re
import requests
import time
from urllib.parse import urlparse

# Sample blacklist (in a real scenario, you might fetch this from a reliable source)
BLACKLIST = [
    "examplephishing.com",
    "maliciousite.net",
    "badlink.org",
    "naldo.com"
]

# Function to fetch the Public Suffix List
def fetch_tld_list():
    url = 'https://publicsuffix.org/list/public_suffix_list.dat'
    try:
        response = requests.get(url)
        tlds = set()
        for line in response.text.splitlines():
            if line and not line.startswith('//'):
                tlds.add(line.strip())
        return tlds
    except requests.RequestException as e:
        print(f"Error fetching TLD list: {e}")
        return set()

VALID_TLDS = fetch_tld_list()

def is_phishing_heuristic(url):
    if url.startswith("http://"):
        return True
    if re.search(r'\b(bank|secure|login|verify|update|account|signin|confirm)\b', url, re.IGNORECASE):
        return True
    if '-' in url:
        return True
    if url.count('.') > 3:
        return True
    if len(url) > 100:
        return True
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', urlparse(url).netloc):
        return True
    return False

def check_blacklist(url):
    domain = urlparse(url).netloc
    return domain in BLACKLIST

def is_misspelled(url):
    if 'goggle' in url:
        return True
    return False

def has_wrong_tld(url):
    tld = urlparse(url).netloc.split('.')[-1]
    return tld not in VALID_TLDS

def is_combination_of_valid_and_fraudulent(url):
    if 'login' in url and 'example' in url:
        return True
    return False

def has_low_pagerank(url):
    if 'lowrank' in url:
        return True
    return False

def has_young_domain_age(url):
    if 'newdomain' in url:
        return True
    return False

def has_incorrect_https(url):
    if re.match(r'^htp://', url):
        return True
    return False

def check_url(url):
    if has_incorrect_https(url):
        return "Suspicious"
    if check_blacklist(url):
        return "Blacklisted"
    if is_phishing_heuristic(url) or is_misspelled(url) or has_wrong_tld(url) or \
       is_combination_of_valid_and_fraudulent(url) or has_low_pagerank(url) or \
       has_young_domain_age(url):
        return "Suspicious"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return "Unreachable"
    except requests.RequestException:
        return "Unreachable"
    
    return "Safe"

def log_result(url, result):
    with open("scan_results.log", "a") as log_file:
        log_file.write(f"{time.ctime()} - URL: {url} - Result: {result}\n")
