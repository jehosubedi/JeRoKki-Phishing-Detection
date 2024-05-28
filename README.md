# Phising-Detection
A project by Team JeRoKki to create a python module that can detect malicious URLs.

WHAT IT DOES?
Blacklisting: Checking URLs against a predefined list of known malicious domains.
Heuristic Analysis: Using more sophisticated heuristics to detect suspicious patterns in URLs.
Logging and Reporting: Logging the scan results to a file and printing a summary.

Blacklist Check: The script contains a hardcoded blacklist of domains known to be malicious. This list can be updated as needed.
Advanced Heuristic Analysis: The is_phishing_heuristic function checks for common phishing tactics:

eywords related to security, banking, and account management.
Presence of hyphens in the domain.
A high number of dots in the domain, which might indicate a subdomain attack.
Request Check: The check_url function attempts to make a request to the URL. If the URL is unreachable or returns a non-200 status code, it's marked as "Unreachable".
Logging and Reporting: The log_result function logs each URL scan result to a file named scan_results.log with a timestamp. The script also maintains a summary of the results and prints it at the end of the scan.

INSTALLATION OF MODULES:
pip install requests

HOW TO USE?
1. git clone the file.
2. access the directory and save it to your choosen directory.
3. run the code by typing "python phising-detection.py" in the terminal.
4. you can now view the results.

REMINDERS!!
always check the modules if they are installed in your system.

  
