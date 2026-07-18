import re

SUSPICIOUS_KEYWORDS = [
    "verify your account", "urgent", "act now", "suspended",
    "click here", "confirm your password", "limited time",
    "you have won", "claim your prize", "update your billing",
    "unusual activity", "security alert", "verify immediately",
    "your account will be closed"
]

SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly", r"tinyurl\.com", r"t\.co", r"goo\.gl",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"-secure-", r"-verify-", r"-update-", r"account-confirm"
]

def find_urls(message):
    url_pattern = r"(https?://[^\s]+|www\.[^\s]+)"
    return re.findall(url_pattern, message, re.IGNORECASE)

def analyze_message(message):
    red_flags = []
    message_lower = message.lower()

    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in message_lower]
    if found_keywords:
        red_flags.append("Urgency/pressure language found: " + ", ".join(found_keywords))

    urls = find_urls(message)
    suspicious_links = []
    for url in urls:
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_links.append(url)
                break
    if suspicious_links:
        red_flags.append("Suspicious link(s) detected: " + ", ".join(suspicious_links))
    elif urls:
        red_flags.append("Link(s) present, verify before clicking: " + ", ".join(urls))

    if re.search(r"\bdear (customer|user|valued member|sir/madam)\b", message_lower):
        red_flags.append("Generic greeting used instead of your name.")

    if re.search(r"\b(password|otp|ssn|card number|cvv|pin)\b", message_lower):
        red_flags.append("Message requests sensitive personal/financial information.")

    if len(red_flags) >= 3:
        verdict = "HIGH RISK - Likely Phishing"
    elif len(red_flags) >= 1:
        verdict = "MEDIUM RISK - Suspicious, Verify Before Acting"
    else:
        verdict = "LOW RISK - No Obvious Red Flags Found"

    return {"verdict": verdict, "red_flags": red_flags}

def print_report(message):
    result = analyze_message(message)
    print("\n=== Phishing Awareness Analysis Report ===")
    print("Verdict:", result["verdict"])
    print("\nRed Flags Identified:")
    if result["red_flags"]:
        for i, flag in enumerate(result["red_flags"], 1):
            print(" ", i, ".", flag)
    else:
        print("  None detected. Still stay cautious.")
    print("=" * 45)

def main():
    print("Phishing Awareness Analysis Tool")
    print("-" * 45)
    while True:
        message = input("\nPaste email/message text (or 'q' to quit):\n")
        if message.strip().lower() == "q":
            print("Goodbye!")
            break
        print_report(message)

if __name__ == "__main__":
    main()
