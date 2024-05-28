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
    # Check if the URL is not using HTTPS
    if url.startswith("http://"):
        return True
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

def display_summary(results_summary):
    print("\nSummary of results:")
    for category, count in results_summary.items():
        print(f"{category}: {count}")

def main():
    results_summary = {
        "Blacklisted": 0,
        "Suspicious": 0,
        "Unreachable": 0,
        "Safe": 0
    }

    while True:
        user_input = input("Enter a URL to check (or 'exit' to quit): ").strip()
        if user_input.lower() == 'exit':
            print("Exiting the program.")
            display_summary(results_summary)
            break

        # Validate URL
        if not re.match(r'^(http|https)://', user_input):
            print("Invalid URL format. Please ensure the URL starts with http:// or https://")
            continue

        result = check_url(user_input)
        log_result(user_input, result)
        results_summary[result] += 1
        print(f"URL: {user_input} is {result}")

        display_summary(results_summary)

if __name__ == "__main__":
    main()
