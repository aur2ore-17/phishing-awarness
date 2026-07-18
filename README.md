# Phishing Awareness Analysis

A Python tool that analyzes email/message text to detect signs of phishing attempts.

## What it does
- Detects suspicious/shortened links (bit.ly, tinyurl, raw IP addresses, etc.)
- Flags urgency and pressure language ("verify immediately", "account suspended", etc.)
- Identifies generic greetings often used in mass phishing ("Dear Customer")
- Flags requests for sensitive information (passwords, OTP, card numbers)
- Gives a final risk verdict: LOW / MEDIUM / HIGH RISK

