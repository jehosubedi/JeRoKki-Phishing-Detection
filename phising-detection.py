import re
import requests
import time
from urllib.parse import urlparse

# Sample blacklist (in a real scenario, you might fetch this from a reliable source)
BLACKLIST = [
    "examplephishing.com",
    "maliciousite.net",
    "badlink.org"
]

# Heuristic checks for phishing
def is_phishing_heuristic(url):
    # Check for common phishing tactics in the URL
    if re.search(r'\b(bank|secure|login|verify|update|account|signin|confirm)\b', url, re.IGNORECASE):
        return True
    if '-' in url:
        return True
    if url.count('.') > 3:
        return True
    return False

def check_blacklist(url):
    # Extract domain from URL
    domain = urlparse(url).netloc
    return domain in BLACKLIST

def check_url(url):
    # Check URL against blacklist
    if check_blacklist(url):
        return "Blacklisted"

    # Perform heuristic analysis
    if is_phishing_heuristic(url):
        return "Suspicious"

    try:
        # Make a request to the URL
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return "Unreachable"
    except requests.RequestException:
        return "Unreachable"

    return "Safe"

def log_result(url, result):
    with open("scan_results.log", "a") as log_file:
        log_file.write(f"{time.ctime()} - URL: {url} - Result: {result}\n")

def main():
    urls_to_check = [
        "http://examplephishing.com",
        "http://safe-website.com",
        "http://suspicious-site.com/login",
        "http://maliciousite.net",
        "http://very.safe-website.com"
    ]

    results_summary = {
        "Blacklisted": 0,
        "Suspicious": 0,
        "Unreachable": 0,
        "Safe": 0
    }

    for url in urls_to_check:
        result = check_url(url)
        log_result(url, result)
        results_summary[result] += 1
        print(f"URL: {url} is {result}")

    print("\nScan complete. Summary of results:")
    for category, count in results_summary.items():
        print(f"{category}: {count}")

if __name__ == "__main__":
    main()


# KEY NOTES
# Blacklisting: Checking URLs against a predefined list of known malicious domains.
# Heuristic Analysis: Using more sophisticated heuristics to detect suspicious patterns in URLs.
# Logging and Reporting: Logging the scan results to a file and printing a summary.

# Explanation
# Blacklist Check: The script contains a hardcoded blacklist of domains known to be malicious. This list can be updated as needed.

# Advanced Heuristic Analysis: The is_phishing_heuristic function checks for common phishing tactics:

# Keywords related to security, banking, and account management.
#Presence of hyphens in the domain.
# A high number of dots in the domain, which might indicate a subdomain attack.
# Request Check: The check_url function attempts to make a request to the URL. If the URL is unreachable or returns a non-200 status code, it's marked as "Unreachable".

# Logging and Reporting: The log_result function logs each URL scan result to a file named scan_results.log with a timestamp. The script also maintains a summary of the results and prints it at the end of the scan.

# Running the Script
# Save and Run: Save the script to a file, for example, enhanced_phishing_scanner.py, and run it using:

# bash
# Copy code
# python enhanced_phishing_scanner.py
# View Results: Check the scan_results.log file for a detailed log of the scan results. The script will also print a summary of the results to the console.

