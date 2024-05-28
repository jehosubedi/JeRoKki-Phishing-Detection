# Phising-Detection
A project by Team JeRoKki to create a python module that can detect malicious URLs.

WHAT IT DOES?
HTTPS Check: In the is_phishing_heuristic function, we check if the URL starts with http:// and mark it as "Suspicious" if it does. This check is done before other heuristic checks.
Summary Tracking and Display:

The results_summary dictionary keeps track of the count of URLs in each category ("Blacklisted," "Suspicious," "Unreachable," and "Safe").
The display_summary function prints the current summary of results to the console after each URL check and when the user exits the program.

User Input Loop: The script prompts the user to enter a URL to check or type exit to quit the program.
For each entered URL, it validates the format, checks the URL, logs the result, updates the summary, and prints the current summary.

INSTALLATION OF MODULES:
pip install requests

HOW TO USE?
1. git clone the file.
2. access the directory and save it to your choosen directory.
3. run the code by typing "python phising-detection.py" in the terminal.
4. type your choosen URL to the terminal for the code to provide the detection of the link.
5. urls should always start with http:// or https:// to be checked. 

REMINDERS!!
always check the modules if they are installed in your system.

Resource:
https://www.youtube.com/watch?v=sCpsr4gH65k&t=21s 

