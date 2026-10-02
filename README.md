# PhishLens

## Project Overview

PhishLens is a cybersecurity prototype developed by Team BYTESTORMS (T05) for TechForge 2026.

It analyzes URLs and QR-code payloads to detect potentially malicious, deceptive, or suspicious destinations. The system provides a SAFE, CAUTION, or DANGER verdict with an explainable risk score.

## Problem Statement

QR codes and links are widely used for payments, authentication, KYC verification, login pages, and communication. Attackers can exploit them using phishing links, deceptive domains, malicious redirects, and fraudulent payment requests.

PhishLens provides a security layer that analyzes these inputs before users interact with them.

## Key Features

- URL threat analysis
- Universal QR-code scanning
- QR payload classification
- UPI payment analysis
- Lookalike-domain detection
- Homoglyph detection
- Suspicious URL detection
- Redirect intelligence
- Domain intelligence
- DNS and TLS analysis
- Explainable risk scoring
- SAFE / CAUTION / DANGER verdicts

## Technology Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, Flask
- **QR Scanning:** HTML5 QR Code
- **Security Analysis:** URL parsing, DNS, TLS, redirect and domain intelligence
- **APIs / Services:** RDAP and optional threat-intelligence services
- **Package Management:** pip
- **Version Control:** Git and GitHub

## Architecture / Workflow

```text
User Input
   ↓
URL or QR Code
   ↓
Decode / Parse
   ↓
Identify Payload Type
   ↓
Threat Analysis
   ├── URL Analysis
   ├── Domain Intelligence
   ├── Redirect Analysis
   ├── Lookalike / Homoglyph Detection
   └── UPI Analysis
   ↓
Risk Scoring
   ↓
SAFE / CAUTION / DANGER
   ↓
Explainable Security Result
```

## Dataset / API Information

PhishLens does not require a machine-learning training dataset.

The system primarily uses rule-based and intelligence-driven analysis of the submitted URL or QR payload.

The backend can use network-based information such as:

- DNS resolution
- HTTP/HTTPS responses
- Redirect information
- TLS information
- RDAP domain registration intelligence
- Optional threat-intelligence services

No project-specific training dataset is required for the current prototype.

## Screenshots / Demo Information

The project demonstration showcases:

- PhishLens dashboard
- URL threat analysis
- SAFE, CAUTION, and DANGER verdicts
- Suspicious URL detection
- QR-code scanning
- QR payload classification
- UPI Shield
- Domain Intelligence
- Risk score and security explanation

### Demo Flow

```text
Enter URL / Scan QR
        ↓
Decode / Analyze
        ↓
Identify Security Signals
        ↓
Calculate Risk Score
        ↓
Display Verdict
        ↓
Explain the Detected Threats
```
## Limitations & Future Scope

### Limitations

- Some websites may block automated requests.
- Some websites may require authentication.
- Some destinations may be temporarily unavailable.
- Complex client-side websites may limit automated analysis.
- A SAFE result does not guarantee that a destination is completely safe.

### Future Scope

- Advanced threat-intelligence integrations
- Improved phishing-page analysis
- Machine-learning-based detection
- More payment-fraud intelligence
- Browser extension
- Mobile application
- Larger threat-intelligence sources
- Advanced QR image processing

## Setup & Installation

### Requirements

- Python 3
- pip
- Modern web browser
- Camera access for QR scanning

### Installation

Clone the repository:

```bash
git clone https://github.com/Rudra-Doke/BYTESTORMS-PhishLens.git
cd BYTESTORMS-PhishLens
```
## Team Members

- Rudra Doke
- Aayush Humne
- Nikhil Dhormale

## Team

**Team Name:** BYTESTORMS  
**Team Number:** T05
