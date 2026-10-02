# PhishLens

### QR & URL Threat Intelligence Scanner

PhishLens is a cybersecurity prototype that analyzes URLs and QR-code payloads to identify potentially malicious, deceptive, or suspicious destinations before a user interacts with them.

It combines URL intelligence, domain analysis, redirect inspection, lookalike-domain detection, UPI analysis, and QR classification into a single security-focused interface.

---

## Problem Statement

QR codes and links are increasingly used for payments, authentication, KYC verification, login pages, promotions, and everyday communication.

Attackers can abuse these channels by creating:

- Phishing URLs
- Lookalike domains
- Homoglyph domains
- Fake KYC/login pages
- Suspicious redirects
- Malicious payment links
- Fraudulent UPI requests
- QR codes containing deceptive payloads

Users often cannot determine whether a link or QR code is trustworthy before opening it.

PhishLens aims to provide a simple security layer that analyzes the destination and explains the detected risk in plain language.

---

## Proposed Solution

PhishLens accepts either:

1. A URL entered manually
2. A QR code scanned through the camera

The system then:

```text
URL / QR Code
      ↓
Decode / Parse
      ↓
Identify Payload Type
      ↓
Analyze URL / Domain / Payment Data
      ↓
Collect Security Signals
      ↓
Calculate Risk
      ↓
SAFE / CAUTION / DANGER
      ↓
Explain the Result
