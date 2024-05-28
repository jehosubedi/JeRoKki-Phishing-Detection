import re
from pd_module import check_url, log_result

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

        if not re.match(r'^(http|https|htp)://', user_input):
            print("Invalid URL format. Please ensure the URL starts with http://, https://, or htp://")
            continue

        result = check_url(user_input)
        log_result(user_input, result)
        results_summary[result] += 1
        print(f"URL: {user_input} is {result}")

        display_summary(results_summary)

if __name__ == "__main__":
    main()