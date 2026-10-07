from flask import Flask, render_template, request, jsonify
from urllib.parse import (
    urlparse,
    parse_qs,
    unquote,
    urljoin
)
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
import socket
import ssl
import json
import os
import time
import requests

from history_service import (
    get_scan_history,
    get_scan_by_id,
    get_scan_statistics,
)

from persistence import persist_scan


app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
@app.after_request
def apply_security_headers(response):
    """Apply baseline security headers to every response."""

    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff",
    )

    response.headers.setdefault(
        "X-Frame-Options",
        "DENY",
    )

    response.headers.setdefault(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
    )

    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(self), microphone=(), geolocation=()",
    )

    if request.is_secure:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

    return response
# ============================================================
# SECURITY HARDENING
# ============================================================

# Reject unexpectedly large request bodies.
# URL/QR payloads are tiny, so 256 KiB is intentionally generous.
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

@app.after_request
def apply_security_headers(response):
    """Apply baseline HTTP security headers to every response."""

    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff",
    )

    response.headers.setdefault(
        "X-Frame-Options",
        "DENY",
    )

    response.headers.setdefault(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
    )

    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(self), microphone=(), geolocation=()",
    )

    # HSTS is only meaningful when the request is already HTTPS.
    if request.is_secure:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

    return response

# ============================================================
# PHISHLENS — MAX THREAT INTELLIGENCE ENGINE
# ============================================================

APP_VERSION = "3.0.0"

USER_AGENT = (
    "PhishLens Threat Intelligence Scanner/3.0 "
    "(Hackathon Prototype)"
)

REQUEST_TIMEOUT = 7
MAX_REDIRECTS = 8
MAX_PAGE_BYTES = 65536


# ============================================================
# OPTIONAL EXTERNAL INTELLIGENCE
# ============================================================

GOOGLE_SAFE_BROWSING_KEY = os.getenv(
    "GOOGLE_SAFE_BROWSING_KEY",
    ""
)

PHISHTANK_APP_KEY = os.getenv(
    "PHISHTANK_APP_KEY",
    ""
)


# ============================================================
# STATIC THREAT KNOWLEDGE
# ============================================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "kyc",
    "password",
    "wallet",
    "payment",
    "claim",
    "urgent",
    "free",
    "bonus",
    "reward",
    "authenticate",
    "authentication",
    "confirm",
    "confirmation",
    "unlock",
    "suspend",
    "suspended",
    "limited",
    "access",
    "billing",
    "invoice",
    "credential",
    "credentials",
    "validate",
    "validation",
    "recover",
    "recovery",
    "support",
    "customer",
    "identity",
    "document",
    "bank",
    "card",
    "refund",
    "prize",
    "gift",
    "offer",
    "security-check",
    "account-check",
    "reauth",
    "signin",
    "session"
]


SECURITY_WORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "password",
    "credential",
    "credentials",
    "authenticate",
    "authentication",
    "kyc",
    "identity",
    "unlock",
    "suspend",
    "suspended",
    "reauth"
}


PAYMENT_WORDS = {
    "payment",
    "wallet",
    "bank",
    "card",
    "billing",
    "invoice",
    "refund",
    "upi",
    "pay",
    "transaction"
}


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "rb.gy",
    "tiny.cc",
    "lnkd.in"
}


TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "github.com",
    "instagram.com",
    "facebook.com",
    "linkedin.com",
    "youtube.com",
    "whatsapp.com",
    "x.com",
    "openai.com",
    "roblox.com",
    "discord.com",
    "netflix.com",
    "spotify.com",
    "adobe.com",
    "dropbox.com",
    "zoom.us",
    "cloudflare.com",
    "wikipedia.org",
    "microsoftonline.com",
    "office.com",
    "live.com",
    "outlook.com"
}


BRAND_BASELINES = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "github": "github.com",
    "instagram": "instagram.com",
    "facebook": "facebook.com",
    "linkedin": "linkedin.com",
    "youtube": "youtube.com",
    "whatsapp": "whatsapp.com",
    "roblox": "roblox.com",
    "discord": "discord.com",
    "netflix": "netflix.com",
    "spotify": "spotify.com",
    "adobe": "adobe.com",
    "dropbox": "dropbox.com",
    "zoom": "zoom.us",
    "openai": "openai.com",
    "microsoftonline": "microsoftonline.com",
    "office": "office.com",
    "outlook": "outlook.com"
}


LOOKALIKE_PATTERNS = [
    ("paypa1", "paypal"),
    ("paypai", "paypal"),
    ("paypaI", "paypal"),
    ("pay-pal", "paypal"),
    ("paypal-", "paypal"),
    ("micros0ft", "microsoft"),
    ("micr0soft", "microsoft"),
    ("m1crosoft", "microsoft"),
    ("g00gle", "google"),
    ("goog1e", "google"),
    ("go0gle", "google"),
    ("faceb00k", "facebook"),
    ("amaz0n", "amazon"),
    ("arnazon", "amazon"),
    ("netf1ix", "netflix"),
    ("app1e", "apple"),
    ("instagrarn", "instagram"),
    ("linkedln", "linkedin"),
    ("rnicrosoft", "microsoft"),
    ("rob1ox", "roblox"),
    ("robl0x", "roblox"),
    ("disc0rd", "discord"),
    ("sp0tify", "spotify")
]


HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t",
    "@": "a"
}


SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "work",
    "support",
    "account",
    "download",
    "stream",
    "fit",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga"
}


REDIRECT_PARAMETER_WORDS = [
    "redirect=",
    "redirect_url=",
    "redirecturl=",
    "url=",
    "next=",
    "return=",
    "returnurl=",
    "continue=",
    "dest=",
    "destination=",
    "target=",
    "goto=",
    "link="
]


COLLECT_INDICATORS = [
    "collect",
    "request",
    "approve",
    "authorization",
    "authorize",
    "accept",
    "permission",
    "collect request",
    "payment request"
]


# ============================================================
# COMMON PUBLIC / PRIVATE NETWORK PROTECTION
# ============================================================

def is_private_or_reserved_ip(value):
    try:
        ip = ipaddress.ip_address(value)

        return (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
        )

    except ValueError:
        return False


def resolve_domain_ips(domain):
    """
    Resolve a hostname and return unique IPs.

    This is used both for intelligence and SSRF protection.
    """

    if not domain:
        return []

    try:
        results = socket.getaddrinfo(
            domain,
            443,
            type=socket.SOCK_STREAM
        )

        ips = []

        for result in results:
            address = result[4][0]

            if address not in ips:
                ips.append(address)

        return ips[:20]

    except (
            socket.gaierror,
            socket.timeout,
            OSError
    ):
        return []


def domain_resolves_publicly(domain):
    ips = resolve_domain_ips(domain)

    if not ips:
        return False, [], False

    private_found = any(
        is_private_or_reserved_ip(ip)
        for ip in ips
    )

    return (
        True,
        ips,
        private_found
    )


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url):
    url = (url or "").strip()

    if not url:
        return ""

    if url.lower().startswith("upi://"):
        return url

    if url.lower().startswith(
            (
                    "http://",
                    "https://"
            )
    ):
        return url

    return "https://" + url


def get_domain(parsed):
    return (
            parsed.hostname
            or ""
    ).lower()


def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True

    except ValueError:
        return False


# ============================================================
# PUBLIC SUFFIX / BASE DOMAIN
# ============================================================

COMMON_TWO_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "com.br",
    "com.cn",
    "com.hk",
    "com.sg",
    "co.in",
    "firm.in",
    "net.in",
    "org.in",
    "gen.in",
    "ind.in",
    "co.jp",
    "co.nz",
    "co.za",
    "com.mx",
    "com.tr",
    "com.ua"
}


def get_base_domain(domain):
    if not domain:
        return ""

    domain = domain.lower().strip()

    if is_ip_address(domain):
        return domain

    parts = domain.split(".")

    if len(parts) <= 2:
        return domain

    suffix = ".".join(parts[-2:])

    if suffix in COMMON_TWO_LEVEL_SUFFIXES:
        if len(parts) >= 3:
            return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def same_base_domain(domain_a, domain_b):
    if not domain_a or not domain_b:
        return False

    return (
            get_base_domain(domain_a)
            ==
            get_base_domain(domain_b)
    )


# ============================================================
# DOMAIN STRUCTURE
# ============================================================

def count_subdomains(domain):
    if not domain or is_ip_address(domain):
        return 0

    base = get_base_domain(domain)

    if not base:
        return 0

    prefix = domain[:-len(base)].rstrip(".")

    if not prefix:
        return 0

    return len(
        [
            item
            for item in prefix.split(".")
            if item
        ]
    )


def get_tld(domain):
    if not domain or is_ip_address(domain):
        return ""

    parts = domain.lower().split(".")

    if len(parts) < 2:
        return ""

    return parts[-1]


def count_hyphens(domain):
    return domain.count("-") if domain else 0


def contains_unicode(domain):
    try:
        domain.encode("ascii")
        return False

    except UnicodeEncodeError:
        return True


def safe_float(value):
    try:
        return float(value)

    except (
            TypeError,
            ValueError
    ):
        return None


# ============================================================
# TRUST / BRAND INTELLIGENCE
# ============================================================

def is_trusted_domain(domain):
    if not domain:
        return False

    return any(
        domain == trusted
        or domain.endswith("." + trusted)
        for trusted in TRUSTED_DOMAINS
    )


def detect_brand_impersonation(domain):
    """
    Detect a brand appearing in a domain that is not
    actually controlled by that brand's expected domain.

    Example:

        roblox.com       -> legitimate baseline
        roblox.com.ml    -> impersonation
        rob1ox-login.xyz -> impersonation
    """

    if not domain:
        return None

    domain_lower = domain.lower()

    for brand, official_domain in BRAND_BASELINES.items():

        if brand not in domain_lower:
            continue

        if (
                domain_lower == official_domain
                or domain_lower.endswith(
            "." + official_domain
        )
        ):
            continue

        return {
            "brand": brand,
            "official_domain": official_domain,
            "detected_domain": domain
        }

    return None


def detect_lookalike(domain):
    domain_lower = domain.lower()

    for fake, real in LOOKALIKE_PATTERNS:

        if fake.lower() in domain_lower:

            return {
                "detected": True,
                "target": real,
                "method": "known substitution"
            }

    normalized = domain_lower

    for original, replacement in HOMOGLYPHS.items():
        normalized = normalized.replace(
            original,
            replacement
        )

    for brand, official_domain in BRAND_BASELINES.items():

        official_base = (
            official_domain
            .split(".")[0]
        )

        current_base = (
            domain_lower
            .split(".")[0]
        )

        if (
                official_base in normalized
                and current_base != official_base
                and len(current_base) >= 5
        ):

            return {
                "detected": True,
                "target": official_domain,
                "method": "normalized brand resemblance"
            }

    return {
        "detected": False,
        "target": None,
        "method": None
    }


def detect_homoglyph(domain):
    if not domain:
        return {
            "detected": False,
            "normalized": ""
        }

    if contains_unicode(domain):

        try:
            normalized = domain.encode(
                "idna"
            ).decode("ascii")

        except Exception:
            normalized = domain

        return {
            "detected": True,
            "normalized": normalized
        }

    normalized = domain
    changed = False

    for original, replacement in HOMOGLYPHS.items():

        if original in normalized:

            normalized = normalized.replace(
                original,
                replacement
            )

            changed = True

    return {
        "detected": changed,
        "normalized": normalized
    }


# ============================================================
# URL PATTERN ANALYSIS
# ============================================================

def find_suspicious_words(text):
    text = (text or "").lower()

    found = []

    for word in SUSPICIOUS_WORDS:

        if word in text:
            found.append(word)

    return list(
        dict.fromkeys(found)
    )


def analyze_domain_structure(domain):

    result = {
        "hyphens": count_hyphens(domain),
        "subdomains": count_subdomains(domain),
        "tld": get_tld(domain),
        "suspicious_tld": False
    }

    if (
            result["tld"]
            in SUSPICIOUS_TLDS
    ):
        result["suspicious_tld"] = True

    return result


# ============================================================
# SAFE NETWORK REQUEST VALIDATION
# ============================================================

def validate_external_url(url):
    """
    Prevent the scanner from requesting:
        localhost
        loopback
        private networks
        link-local addresses
        reserved addresses
        obvious cloud metadata targets
    """

    try:
        parsed = urlparse(url)

    except Exception:
        return False, "Invalid URL."

    if parsed.scheme not in (
            "http",
            "https"
    ):
        return False, "Unsupported network scheme."

    domain = get_domain(parsed)

    if not domain:
        return False, "No destination hostname."

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata"
    }

    if domain in blocked_names:
        return False, "Local or metadata destination blocked."

    if is_ip_address(domain):

        if is_private_or_reserved_ip(domain):
            return (
                False,
                "Private or reserved destination blocked."
            )

        return True, "Public IP destination."

    resolves, ips, private_found = (
        domain_resolves_publicly(domain)
    )

    if not resolves:
        return False, "Domain does not resolve."

    if private_found:
        return (
            False,
            "Domain resolves to a private/reserved address."
        )

    return True, "Public destination."


# ============================================================
# LIVE REDIRECT / HTTP ANALYSIS
# ============================================================

def inspect_live_destination(start_url):
    """
    Follow redirects manually.

    This allows every hop to be checked before the server
    makes the next request.
    """

    chain = [start_url]

    current_url = start_url

    statuses = []

    final_response = None

    request_error = None

    for _ in range(MAX_REDIRECTS + 1):

        valid, reason = validate_external_url(
            current_url
        )

        if not valid:

            request_error = reason
            break

        try:

            response = requests.get(
                current_url,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                stream=True,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": (
                        "text/html,"
                        "application/xhtml+xml,"
                        "application/json,"
                        "text/plain,"
                        "*/*"
                    )
                }
            )

            final_response = response

            statuses.append(
                {
                    "url": current_url,
                    "status": response.status_code,
                    "content_type": (
                        response.headers.get(
                            "Content-Type",
                            ""
                        )
                    )[:120]
                }
            )

            location = response.headers.get(
                "Location"
            )

            if (
                    response.status_code
                    in (
                    301,
                    302,
                    303,
                    307,
                    308
            )
                    and location
            ):

                next_url = urljoin(
                    current_url,
                    location
                )

                if next_url in chain:
                    request_error = (
                        "Redirect loop detected."
                    )
                    break

                chain.append(next_url)
                current_url = next_url

                response.close()

                continue

            break

        except requests.RequestException as exc:

            request_error = (
                str(exc)
            )

            break

    final_url = (
        chain[-1]
        if chain
        else start_url
    )

    return {
        "chain": chain,
        "statuses": statuses,
        "final_url": final_url,
        "final_response": final_response,
        "error": request_error
    }


# ============================================================
# PAGE INTELLIGENCE
# ============================================================

def inspect_page_response(response):

    if response is None:

        return {
            "available": False,
            "status": None,
            "content_type": "",
            "server": "",
            "title": None,
            "bytes_sampled": 0
        }

    content_type = (
        response.headers.get(
            "Content-Type",
            ""
        )
    )

    server = (
        response.headers.get(
            "Server",
            ""
        )
    )

    title = None
    bytes_sampled = 0

    try:

        if (
                "text/html"
                in content_type.lower()
        ):

            chunks = []

            remaining = MAX_PAGE_BYTES

            while remaining > 0:

                chunk = next(
                    response.iter_content(
                        chunk_size=min(
                            8192,
                            remaining
                        )
                    ),
                    b""
                )

                if not chunk:
                    break

                chunks.append(chunk)

                remaining -= len(chunk)

            raw = b"".join(chunks)

            bytes_sampled = len(raw)

            text = raw.decode(
                "utf-8",
                errors="ignore"
            )

            match = re.search(
                r"<title[^>]*>(.*?)</title>",
                text,
                re.IGNORECASE | re.DOTALL
            )

            if match:
                title = re.sub(
                    r"\s+",
                    " ",
                    unquote(
                        match.group(1)
                    )
                ).strip()[:200]

    except Exception:
        pass

    try:
        response.close()
    except Exception:
        pass

    return {
        "available": True,
        "status": response.status_code,
        "content_type": content_type[:160],
        "server": server[:120],
        "title": title,
        "bytes_sampled": bytes_sampled
    }


# ============================================================
# TLS CERTIFICATE INTELLIGENCE
# ============================================================

def inspect_tls_certificate(domain, port=443):

    if not domain:
        return {
            "available": False
        }

    if is_ip_address(domain):
        return {
            "available": False,
            "reason": "IP destination"
        }

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
                (domain, port),
                timeout=5
        ) as raw_socket:

            with context.wrap_socket(
                    raw_socket,
                    server_hostname=domain
            ) as tls_socket:

                certificate = (
                    tls_socket.getpeercert()
                )

                not_before = (
                    certificate.get(
                        "notBefore"
                    )
                )

                not_after = (
                    certificate.get(
                        "notAfter"
                    )
                )

                issuer = (
                    certificate.get(
                        "issuer",
                        []
                    )
                )

                subject = (
                    certificate.get(
                        "subject",
                        []
                    )
                )

                return {
                    "available": True,
                    "valid": True,
                    "not_before": not_before,
                    "not_after": not_after,
                    "issuer": str(issuer)[:500],
                    "subject": str(subject)[:500],
                    "tls_version": (
                        tls_socket.version()
                    )
                }

    except Exception as exc:

        return {
            "available": True,
            "valid": False,
            "error": str(exc)[:250]
        }


# ============================================================
# RDAP INTELLIGENCE
# ============================================================

_RDAP_BOOTSTRAP_CACHE = {
    "timestamp": 0,
    "data": None
}


def get_rdap_bootstrap():

    now = time.time()

    if (
            _RDAP_BOOTSTRAP_CACHE["data"]
            and now
            - _RDAP_BOOTSTRAP_CACHE["timestamp"]
            < 86400
    ):
        return (
            _RDAP_BOOTSTRAP_CACHE["data"]
        )

    try:

        response = requests.get(
            "https://data.iana.org/rdap/dns.json",
            timeout=6,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        response.raise_for_status()

        data = response.json()

        _RDAP_BOOTSTRAP_CACHE[
            "timestamp"
        ] = now

        _RDAP_BOOTSTRAP_CACHE[
            "data"
        ] = data

        return data

    except Exception:

        return None


def get_rdap_server(tld):

    data = get_rdap_bootstrap()

    if not data:
        return None

    for service in data.get(
            "services",
            []
    ):

        if len(service) != 2:
            continue

        tlds = service[0]
        urls = service[1]

        if tld in tlds and urls:
            return urls[0]

    return None


def parse_rdap_date(value):

    if not value:
        return None

    try:
        value = value.replace(
            "Z",
            "+00:00"
        )

        return datetime.fromisoformat(
            value
        )

    except Exception:
        return None


def inspect_rdap(domain):

    if (
            not domain
            or is_ip_address(domain)
    ):
        return {
            "available": False,
            "reason": "IP destination"
        }

    tld = get_tld(domain)

    if not tld:
        return {
            "available": False,
            "reason": "No TLD"
        }

    server = get_rdap_server(tld)

    if not server:
        return {
            "available": False,
            "reason": "No RDAP server discovered"
        }

    endpoint = (
            server.rstrip("/")
            + "/domain/"
            + domain
    )

    try:

        response = requests.get(
            endpoint,
            timeout=6,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": USER_AGENT
            }
        )

        if response.status_code != 200:

            return {
                "available": False,
                "status": response.status_code,
                "server": server
            }

        data = response.json()

        events = {}

        for event in data.get(
                "events",
                []
        ):

            action = event.get(
                "eventAction"
            )

            date = event.get(
                "eventDate"
            )

            if action and date:
                events[action] = date

        registration_date = (
            events.get(
                "registration"
            )
        )

        expiration_date = (
            events.get(
                "expiration"
            )
        )

        age_days = None

        parsed_registration = (
            parse_rdap_date(
                registration_date
            )
        )

        if parsed_registration:

            age_days = max(
                0,
                (
                        datetime.now(
                            timezone.utc
                        )
                        - parsed_registration
                ).days
            )

        return {
            "available": True,
            "status": 200,
            "server": server,
            "domain": data.get(
                "ldhName",
                domain
            ),
            "registration": registration_date,
            "expiration": expiration_date,
            "age_days": age_days,
            "status_values": data.get(
                "status",
                []
            )
        }

    except Exception as exc:

        return {
            "available": False,
            "server": server,
            "error": str(exc)[:250]
        }


# ============================================================
# GOOGLE SAFE BROWSING
# ============================================================

def google_safe_browsing_lookup(url):

    if not GOOGLE_SAFE_BROWSING_KEY:

        return {
            "configured": False,
            "checked": False,
            "matched": False,
            "reason": "API key not configured."
        }

    endpoint = (
            "https://safebrowsing.googleapis.com/"
            "v4/threatMatches:find"
            "?key="
            + GOOGLE_SAFE_BROWSING_KEY
    )

    payload = {
        "client": {
            "clientId": "phishlens",
            "clientVersion": APP_VERSION
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    try:

        response = requests.post(
            endpoint,
            json=payload,
            timeout=7,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        if response.status_code != 200:

            return {
                "configured": True,
                "checked": False,
                "matched": False,
                "error": (
                        "Safe Browsing HTTP "
                        + str(response.status_code)
                )
            }

        data = response.json()

        matches = data.get(
            "matches",
            []
        )

        return {
            "configured": True,
            "checked": True,
            "matched": bool(matches),
            "matches": [
                {
                    "threat_type": item.get(
                        "threatType"
                    ),
                    "platform": item.get(
                        "platformType"
                    )
                }
                for item in matches
            ]
        }

    except Exception as exc:

        return {
            "configured": True,
            "checked": False,
            "matched": False,
            "error": str(exc)[:250]
        }


# ============================================================
# PHISHTANK
# ============================================================

def phishtank_lookup(url):

    endpoint = (
        "https://checkurl.phishtank.com/"
        "checkurl/"
    )

    payload = {
        "url": url,
        "format": "json"
    }

    if PHISHTANK_APP_KEY:
        payload["app_key"] = (
            PHISHTANK_APP_KEY
        )

    try:

        response = requests.post(
            endpoint,
            data=payload,
            timeout=7,
            headers={
                "User-Agent": (
                    "PhishLens/3.0 "
                    "Security Research"
                )
            }
        )

        if response.status_code != 200:

            return {
                "configured": bool(
                    PHISHTANK_APP_KEY
                ),
                "checked": False,
                "matched": False,
                "error": (
                        "PhishTank HTTP "
                        + str(response.status_code)
                )
            }

        data = response.json()

        results = data.get(
            "results",
            {}
        )

        return {
            "configured": True,
            "checked": True,
            "matched": bool(
                results.get(
                    "in_database",
                    False
                )
                and results.get(
                    "valid",
                    False
                )
            ),
            "in_database": results.get(
                "in_database",
                False
            ),
            "valid": results.get(
                "valid",
                False
            ),
            "verified": results.get(
                "verified",
                False
            )
        }

    except Exception as exc:

        return {
            "configured": bool(
                PHISHTANK_APP_KEY
            ),
            "checked": False,
            "matched": False,
            "error": str(exc)[:250]
        }


# ============================================================
# UPI INTELLIGENCE
# ============================================================

def analyze_upi(url):

    if not url.lower().startswith(
            "upi://"
    ):
        return None

    parsed = urlparse(url)

    params = parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    payee = params.get(
        "pa",
        [""]
    )[0]

    payee_name = params.get(
        "pn",
        [""]
    )[0]

    amount = params.get(
        "am",
        [""]
    )[0]

    currency = params.get(
        "cu",
        [""]
    )[0]

    risk = 0
    reasons = []

    combined = (
            payee
            + " "
            + payee_name
    ).lower()

    found_security = [
        word
        for word in SECURITY_WORDS
        if word in combined
    ]

    if found_security:

        risk += min(
            45,
            20 + len(found_security) * 6
        )

        reasons.append(
            "The payment information contains "
            "security or verification language."
        )

    if not payee:

        risk += 30

        reasons.append(
            "The UPI payment does not specify "
            "a payee ID."
        )

    collect_detected = any(
        word in combined
        for word in COLLECT_INDICATORS
    )

    if collect_detected:

        risk += 30

        reasons.append(
            "The payment data contains language "
            "associated with a payment request "
            "or authorization."
        )

    payment_words = [
        word
        for word in PAYMENT_WORDS
        if word in combined
    ]

    if len(payment_words) >= 2:

        risk += 10

        reasons.append(
            "Multiple payment-related terms appear "
            "in the payment information."
        )

    numeric_amount = safe_float(
        amount
    )

    if amount:

        if numeric_amount is None:

            risk += 20

            reasons.append(
                "The payment amount could not "
                "be validated."
            )

        elif numeric_amount <= 0:

            risk += 25

            reasons.append(
                "The payment amount is invalid."
            )

    if (
            numeric_amount is not None
            and numeric_amount >= 100000
    ):

        risk += 10

        reasons.append(
            "The payment amount is unusually high."
        )

    risk = min(
        risk,
        100
    )

    if risk >= 60:
        status = "HIGH RISK"

    elif risk >= 30:
        status = "REVIEW"

    else:
        status = "NO UPI SIGNAL"

    if not reasons:

        reasons.append(
            "No major UPI-specific warning "
            "was detected."
        )

    return {
        "payee": payee or None,
        "payee_name": payee_name or None,
        "amount": amount or None,
        "currency": currency or None,
        "risk": risk,
        "status": status,
        "collect_detected": collect_detected,
        "reasons": reasons,
        "message": (
            reasons[0]
            if reasons
            else "No UPI-specific warning."
        )
    }


# ============================================================
# UNIVERSAL QR / PAYLOAD CLASSIFICATION
# ============================================================

def classify_payload(payload):

    raw = (
            payload
            or ""
    ).strip()

    lower = raw.lower()

    if not raw:

        return {
            "type": "UNKNOWN",
            "display": "Empty QR payload",
            "data": {}
        }

    if lower.startswith(
            "upi://"
    ):

        upi = analyze_upi(raw)

        return {
            "type": "UPI PAYMENT",
            "display": "UPI payment request",
            "data": upi or {}
        }

    if lower.startswith(
            "wifi:"
    ):

        content = raw[5:]

        fields = {}

        for part in re.split(
                r";(?=[A-Z]+:)",
                content
        ):

            if ":" not in part:
                continue

            key, value = part.split(
                ":",
                1
            )

            fields[
                key.lower()
            ] = value

        security = fields.get(
            "t",
            ""
        )

        ssid = fields.get(
            "s",
            ""
        )

        hidden = fields.get(
            "h",
            ""
        )

        return {
            "type": "WI-FI",
            "display": "Wi-Fi network configuration",
            "data": {
                "ssid": ssid,
                "security": security,
                "hidden": hidden
            }
        }

    if (
            lower.startswith(
                "begin:vcard"
            )
    ):

        name = None
        phone = None
        email = None
        organization = None

        for line in raw.splitlines():

            if line.upper().startswith(
                    "FN:"
            ):
                name = line[3:].strip()

            elif line.upper().startswith(
                    "TEL:"
            ):
                phone = line[4:].strip()

            elif line.upper().startswith(
                    "EMAIL:"
            ):
                email = line[6:].strip()

            elif line.upper().startswith(
                    "ORG:"
            ):
                organization = line[4:].strip()

        return {
            "type": "CONTACT",
            "display": "Contact / vCard",
            "data": {
                "name": name,
                "phone": phone,
                "email": email,
                "organization": organization
            }
        }

    if lower.startswith(
            "mailto:"
    ):

        parsed = urlparse(raw)

        return {
            "type": "EMAIL",
            "display": "Email address",
            "data": {
                "email": parsed.path,
                "parameters": parse_qs(
                    parsed.query
                )
            }
        }

    if lower.startswith(
            "tel:"
    ):

        return {
            "type": "TELEPHONE",
            "display": "Telephone number",
            "data": {
                "telephone": raw[4:]
            }
        }

    if lower.startswith(
            "sms:"
    ):

        parsed = urlparse(raw)

        return {
            "type": "SMS",
            "display": "SMS message",
            "data": {
                "destination": parsed.path,
                "message": parse_qs(
                    parsed.query
                )
            }
        }

    if (
            lower.startswith(
                "intent:"
            )
            or lower.startswith(
        "android-app:"
    )
            or lower.startswith(
        "app://"
    )
            or lower.startswith(
        "market://"
    )
    ):

        return {
            "type": "APP / DEEP LINK",
            "display": "Application or deep link",
            "data": {
                "payload": raw[:1000]
            }
        }

    if lower.startswith(
            (
                    "http://",
                    "https://"
            )
    ):

        return {
            "type": "URL",
            "display": "Web URL",
            "data": {
                "url": raw
            }
        }

    if (
            re.match(
                r"^[a-z0-9.-]+\.[a-z]{2,}(/.*)?$",
                lower
            )
    ):

        normalized = normalize_url(
            raw
        )

        return {
            "type": "URL",
            "display": "Web URL",
            "data": {
                "url": normalized
            }
        }

    return {
        "type": "TEXT",
        "display": "Plain text",
        "data": {
            "text": raw[:2000]
        }
    }


# ============================================================
# UNIVERSAL NON-URL PAYLOAD RESULT
# ============================================================

def analyze_non_url_payload(
        payload,
        classification
):

    qr_type = classification[
        "type"
    ]

    info = classification.get(
        "data",
        {}
    )

    reasons = [
        f"QR content identified as {qr_type}."
    ]

    risk = 0

    if qr_type == "APP / DEEP LINK":

        risk = 25

        reasons.append(
            "Application deep links can open "
            "another app or action, so verify "
            "the source before proceeding."
        )

    elif qr_type == "WI-FI":

        risk = 5

        reasons.append(
            "This QR contains Wi-Fi configuration "
            "data rather than a website."
        )

    elif qr_type == "CONTACT":

        risk = 5

        reasons.append(
            "This QR contains contact information "
            "rather than a website."
        )

    elif qr_type == "EMAIL":

        risk = 5

        reasons.append(
            "This QR contains an email destination."
        )

    elif qr_type == "TELEPHONE":

        risk = 5

        reasons.append(
            "This QR contains a telephone destination."
        )

    elif qr_type == "SMS":

        risk = 10

        reasons.append(
            "This QR contains an SMS destination."
        )

    elif qr_type == "TEXT":

        risk = 0

        reasons.append(
            "No web destination was found in the QR."
        )

    verdict = (
        "DANGER"
        if risk >= 60
        else "CAUTION"
        if risk >= 30
        else "SAFE"
    )

    return {
        "score": risk,
        "risk_score": risk,
        "verdict": verdict,
        "domain": qr_type,
        "final_domain": "",
        "reasons": reasons,
        "redirect_chain": [],
        "domain_intelligence": {
            "domain": qr_type,
            "type": qr_type,
            "trusted": False,
            "subdomains": 0,
            "lookalike": False,
            "homoglyph": False,
            "reputation": "NON-WEB PAYLOAD",
            "final_domain": ""
        },
        "signals": {
            "url": risk,
            "domain": 0,
            "redirect": 0,
            "security": risk
        },
        "confidence": 90,
        "query_hash": None,
        "upi": None,
        "upi_risk": 0,
        "qr": {
            "type": qr_type,
            "display": classification.get(
                "display"
            ),
            "data": info,
            "raw_preview": (
                payload[:300]
            )
        },
        "live_intelligence": {
            "checked": False
        }
    }


# ============================================================
# MAIN URL ENGINE
# ============================================================

def analyze_url(url):

    if not url:

        return {
            "score": 100,
            "risk_score": 100,
            "verdict": "DANGER",
            "domain": "",
            "final_domain": "",
            "reasons": [
                "No URL was provided."
            ],
            "redirect_chain": [],
            "domain_intelligence": {},
            "signals": {},
            "confidence": 0,
            "query_hash": None,
            "upi": None,
            "upi_risk": 100,
            "live_intelligence": {}
        }

    url = normalize_url(
        url
    )

    query_hash = (
        hash_query_parameters(
            url
        )
    )

    # --------------------------------------------------------
    # UPI
    # --------------------------------------------------------

    upi = analyze_upi(
        url
    )

    if upi:

        score = upi["risk"]

        verdict = (
            "DANGER"
            if score >= 60
            else "CAUTION"
            if score >= 30
            else "SAFE"
        )

        return {
            "score": score,
            "risk_score": score,
            "verdict": verdict,
            "domain": "UPI PAYMENT",
            "final_domain": "",
            "reasons": upi["reasons"],
            "redirect_chain": [],
            "domain_intelligence": {
                "domain": "UPI PAYMENT",
                "type": "PAYMENT URI",
                "trusted": False,
                "subdomains": 0,
                "lookalike": False,
                "lookalike_target": None,
                "homoglyph": False,
                "final_domain": "",
                "reputation": "PAYMENT"
            },
            "signals": {
                "url": min(
                    score + 5,
                    100
                ),
                "domain": 10,
                "redirect": 0,
                "security": score
            },
            "confidence": 92,
            "query_hash": query_hash,
            "upi": upi,
            "upi_risk": score,
            "live_intelligence": {
                "checked": False,
                "type": "UPI"
            }
        }

    # --------------------------------------------------------
    # PARSE
    # --------------------------------------------------------

    try:

        parsed = urlparse(
            url
        )

    except Exception:

        return {
            "score": 100,
            "risk_score": 100,
            "verdict": "DANGER",
            "domain": "",
            "final_domain": "",
            "reasons": [
                "The URL could not be parsed."
            ],
            "redirect_chain": [],
            "domain_intelligence": {},
            "signals": {},
            "confidence": 95,
            "query_hash": query_hash,
            "upi": None,
            "upi_risk": 0,
            "live_intelligence": {}
        }

    if parsed.scheme not in (
            "http",
            "https"
    ):

        classification = classify_payload(
            url
        )

        return analyze_non_url_payload(
            url,
            classification
        )

    domain = get_domain(
        parsed
    )

    path = (
            parsed.path
            or ""
    ).lower()

    full_url = url.lower()

    score = 0

    reasons = []

    url_risk = 0
    domain_risk = 0
    redirect_risk = 0
    security_risk = 0

    # --------------------------------------------------------
    # DOMAIN STRUCTURE
    # --------------------------------------------------------

    structure = (
        analyze_domain_structure(
            domain
        )
    )

    suspicious_tld = structure[
        "suspicious_tld"
    ]

    hyphens = structure[
        "hyphens"
    ]

    subdomains = structure[
        "subdomains"
    ]

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if parsed.scheme != "https":

        score += 20
        security_risk += 35

        reasons.append(
            "The website does not use HTTPS."
        )

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    ip_address = is_ip_address(
        domain
    )

    if ip_address:

        score += 30
        domain_risk += 45
        url_risk += 25

        reasons.append(
            "The URL uses an IP address "
            "instead of a normal domain."
        )

    # --------------------------------------------------------
    # LONG URL
    # --------------------------------------------------------

    if len(url) > 100:

        score += 10
        url_risk += 20

        reasons.append(
            "The URL is unusually long."
        )

    # --------------------------------------------------------
    # DOMAIN LENGTH
    # --------------------------------------------------------

    if len(domain) >= 35:

        score += 8
        domain_risk += 15

        reasons.append(
            "The domain name is unusually long."
        )

    # --------------------------------------------------------
    # HYPHENS
    # --------------------------------------------------------

    if hyphens >= 3:

        score += 12
        domain_risk += 20

        reasons.append(
            "The domain contains many hyphens, "
            "a pattern sometimes used in deceptive domains."
        )

    elif hyphens == 2:

        score += 5
        domain_risk += 8

    # --------------------------------------------------------
    # TLD
    # --------------------------------------------------------

    if suspicious_tld:

        score += 12
        domain_risk += 18

        reasons.append(
            "The domain uses the ."
            + structure["tld"]
            + " top-level domain, "
              "which can require extra caution."
        )

    # --------------------------------------------------------
    # SUSPICIOUS WORDS
    # --------------------------------------------------------

    found_words = find_suspicious_words(
        full_url
    )

    found_security_words = [
        word
        for word in found_words
        if word in SECURITY_WORDS
    ]

    found_payment_words = [
        word
        for word in found_words
        if word in PAYMENT_WORDS
    ]

    word_count = len(
        found_words
    )

    if word_count >= 5:

        score += 32
        url_risk += 40

        reasons.append(
            "The URL contains many high-risk "
            "words commonly associated with "
            "account or verification scams."
        )

    elif word_count >= 4:

        score += 27
        url_risk += 35

        reasons.append(
            "The URL combines several sensitive "
            "security or account-related terms."
        )

    elif word_count >= 3:

        score += 22
        url_risk += 30

        reasons.append(
            "The URL contains multiple sensitive "
            "terms such as "
            + ", ".join(
                found_words[:4]
            )
            + "."
        )

    elif word_count == 2:

        score += 10
        url_risk += 15

        reasons.append(
            "The URL contains multiple "
            "security-sensitive terms."
        )

    elif word_count == 1:

        score += 4
        url_risk += 7

    # --------------------------------------------------------
    # SECURITY COMBINATION
    # --------------------------------------------------------

    if len(
            found_security_words
    ) >= 3:

        score += 18
        domain_risk += 12

        reasons.append(
            "The URL combines several account-security "
            "terms such as login, verification or password."
        )

    elif len(
            found_security_words
    ) == 2:

        score += 8
        domain_risk += 6

    # --------------------------------------------------------
    # PAYMENT + SECURITY
    # --------------------------------------------------------

    if (
            found_payment_words
            and found_security_words
    ):

        score += 15
        domain_risk += 12

        reasons.append(
            "Payment-related and account-security "
            "language appear together in the destination."
        )

    # --------------------------------------------------------
    # DOMAIN WORDS
    # --------------------------------------------------------

    domain_words = re.split(
        r"[^a-z0-9]+",
        domain
    )

    domain_words = [
        word
        for word in domain_words
        if word
    ]

    domain_sensitive_words = [
        word
        for word in domain_words
        if (
                word in SECURITY_WORDS
                or word in PAYMENT_WORDS
        )
    ]

    if len(
            domain_sensitive_words
    ) >= 3:

        score += 18
        domain_risk += 25

        reasons.append(
            "The domain itself combines multiple "
            "security or payment terms in a "
            "phishing-style pattern."
        )

    elif len(
            domain_sensitive_words
    ) == 2:

        score += 10
        domain_risk += 15

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        score += 25
        url_risk += 35

        reasons.append(
            "The URL contains an @ symbol, "
            "which can hide the real destination."
        )

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    if subdomains >= 3:

        score += 20
        domain_risk += 30

        reasons.append(
            "The domain contains an unusually "
            "large number of subdomains."
        )

    elif subdomains >= 2:

        score += 12
        domain_risk += 20

        reasons.append(
            "The domain contains multiple subdomains."
        )

    # --------------------------------------------------------
    # SHORTENER
    # --------------------------------------------------------

    is_shortener = (
            domain in SHORTENERS
    )

    if is_shortener:

        score += 20
        redirect_risk += 35

        reasons.append(
            "This is a URL-shortening service, "
            "so the final destination is hidden."
        )

    # --------------------------------------------------------
    # ENCODING
    # --------------------------------------------------------

    encoded_count = url.count(
        "%"
    )

    if encoded_count >= 3:

        score += 10
        url_risk += 18

        reasons.append(
            "The URL contains several encoded characters."
        )

    elif encoded_count > 0:

        score += 5
        url_risk += 10

    # --------------------------------------------------------
    # DOUBLE SLASH
    # --------------------------------------------------------

    if "//" in path:

        score += 5
        url_risk += 8

        reasons.append(
            "The URL path contains an unusual "
            "double-slash pattern."
        )

    # --------------------------------------------------------
    # REDIRECT PARAMETERS
    # --------------------------------------------------------

    redirect_parameter_detected = any(
        word in full_url
        for word in REDIRECT_PARAMETER_WORDS
    )

    if redirect_parameter_detected:

        score += 10
        redirect_risk += 25

        reasons.append(
            "The URL contains a parameter that "
            "can redirect the visitor to another destination."
        )

    # --------------------------------------------------------
    # PATH
    # --------------------------------------------------------

    path_words = find_suspicious_words(
        path
    )

    if len(path_words) >= 3:

        score += 15
        url_risk += 20

        reasons.append(
            "The page path contains several "
            "account or verification terms."
        )

    # --------------------------------------------------------
    # LOOKALIKE
    # --------------------------------------------------------

    lookalike = detect_lookalike(
        domain
    )

    if lookalike["detected"]:

        score += 40
        domain_risk += 55

        reasons.append(
            "The domain resembles "
            + str(
                lookalike["target"]
            )
            + " but uses altered characters."
        )

    # --------------------------------------------------------
    # HOMOGLYPH
    # --------------------------------------------------------

    homoglyph = detect_homoglyph(
        domain
    )

    if homoglyph["detected"]:

        score += 25
        domain_risk += 40

        reasons.append(
            "The domain contains characters "
            "that may visually imitate normal "
            "domain characters."
        )

    # --------------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------------

    brand_impersonation = (
        detect_brand_impersonation(
            domain
        )
    )

    if brand_impersonation:

        score += 45
        domain_risk += 60

        reasons.append(
            "The domain contains the brand name '"
            + brand_impersonation["brand"]
            + "' but is not the official "
            + brand_impersonation["official_domain"]
            + " domain."
        )

    # --------------------------------------------------------
    # TRUST
    # --------------------------------------------------------

    trusted = is_trusted_domain(
        domain
    )

    if trusted:

        score = max(
            0,
            score - 15
        )

        domain_risk = max(
            0,
            domain_risk - 30
        )

    # ========================================================
    # LIVE DNS INTELLIGENCE
    # ========================================================

    dns_resolved = False
    resolved_ips = []
    private_resolution = False

    if not ip_address:

        (
            dns_resolved,
            resolved_ips,
            private_resolution
        ) = domain_resolves_publicly(
            domain
        )

        if not dns_resolved:

            score += 25
            domain_risk += 25

            reasons.append(
                "The domain could not be resolved by DNS."
            )

    else:

        dns_resolved = True
        resolved_ips = [domain]

    # ========================================================
    # LIVE HTTP / REDIRECT INTELLIGENCE
    # ========================================================

    live = inspect_live_destination(
        url
    )

    redirect_chain = live[
        "chain"
    ]

    redirect_count = max(
        0,
        len(redirect_chain) - 1
    )

    final_url = live[
        "final_url"
    ]

    final_parsed = urlparse(
        final_url
    )

    final_domain = get_domain(
        final_parsed
    )

    # ========================================================
    # REDIRECT RISK
    # ========================================================

    if redirect_count > 0:

        same_site_redirect = (
                bool(final_domain)
                and same_base_domain(
            domain,
            final_domain
        )
        )

        if (
                same_site_redirect
                and trusted
        ):

            redirect_risk += min(
                redirect_count * 2,
                6
            )

        else:

            redirect_risk += min(
                redirect_count * 15,
                50
            )

            score += min(
                redirect_count * 5,
                15
            )

            reasons.append(
                "The URL passed through "
                + str(redirect_count)
                + " redirect(s) before reaching "
                  "its final destination."
            )

    # ========================================================
    # DESTINATION CHANGE
    # ========================================================

    destination_changed = (
            bool(final_domain)
            and not same_base_domain(
        domain,
        final_domain
    )
    )

    if destination_changed:

        score += 15
        redirect_risk += 25

        reasons.append(
            "The destination changed from "
            + domain
            + " to "
            + final_domain
            + "."
        )

    # ========================================================
    # FINAL DESTINATION BRAND CHECK
    # ========================================================

    final_brand = None

    if final_domain:

        final_brand = (
            detect_brand_impersonation(
                final_domain
            )
        )

        final_lookalike = (
            detect_lookalike(
                final_domain
            )
        )

        if (
                final_lookalike["detected"]
                and not lookalike["detected"]
        ):

            score += 25
            domain_risk += 35

            reasons.append(
                "The final destination resembles "
                + str(
                    final_lookalike["target"]
                )
                + "."
            )

        if (
                final_brand
                and not brand_impersonation
        ):

            score += 30
            domain_risk += 40

            reasons.append(
                "The final destination appears to "
                "use a brand name outside its official domain."
            )

    # ========================================================
    # HTTP STATUS
    # ========================================================

    statuses = live[
        "statuses"
    ]

    final_status = None

    if statuses:

        final_status = statuses[-1].get(
            "status"
        )

    if final_status:

        if final_status >= 500:

            score += 5

            reasons.append(
                "The final server returned a "
                "server-side error."
            )

        elif final_status == 404:

            score += 3

            reasons.append(
                "The final destination returned HTTP 404."
            )

    # ========================================================
    # PAGE INTELLIGENCE
    # ========================================================

    page_info = inspect_page_response(
        live["final_response"]
    )

    # ========================================================
    # TLS INTELLIGENCE
    # ========================================================

    tls_info = None

    if (
            final_parsed.scheme
            == "https"
    ):

        tls_info = (
            inspect_tls_certificate(
                final_domain
            )
        )

        if (
                tls_info.get(
                    "available"
                )
                and not tls_info.get(
            "valid",
            False
        )
        ):

            score += 20
            security_risk += 30

            reasons.append(
                "The TLS certificate could not "
                "be validated successfully."
            )

    # ========================================================
    # RDAP / REGISTRATION AGE
    # ========================================================

    rdap = inspect_rdap(
        final_domain
        or domain
    )

    if rdap.get(
            "available"
    ):

        age_days = rdap.get(
            "age_days"
        )

        if (
                age_days is not None
                and age_days <= 7
        ):

            score += 25
            domain_risk += 35

            reasons.append(
                "The final domain appears to have "
                "been registered very recently."
            )

        elif (
                age_days is not None
                and age_days <= 30
        ):

            score += 12
            domain_risk += 18

            reasons.append(
                "The final domain appears to be "
                "less than 30 days old."
            )

    # ========================================================
    # GOOGLE SAFE BROWSING
    # ========================================================

    safe_browsing = (
        google_safe_browsing_lookup(
            final_url
        )
    )

    if safe_browsing.get(
            "matched"
    ):

        score += 70
        security_risk += 80

        reasons.append(
            "Google Safe Browsing reported this "
            "destination on an unsafe-resource list."
        )

    # ========================================================
    # PHISHTANK
    # ========================================================

    phishtank = (
        phishtank_lookup(
            final_url
        )
    )

    if phishtank.get(
            "matched"
    ):

        score += 65
        security_risk += 75

        reasons.append(
            "PhishTank reported this URL as "
            "a verified phishing entry."
        )

    # ========================================================
    # HTTPS SECURITY SIGNAL
    # ========================================================

    if parsed.scheme == "https":

        security_risk += 5

    if trusted:

        security_risk = max(
            0,
            security_risk - 15
        )

    # ========================================================
    # HIGH-RISK COMBINATIONS
    # ========================================================

    if (
            ip_address
            and parsed.scheme != "https"
            and word_count >= 2
    ):

        score += 20
        security_risk += 20

        reasons.append(
            "The destination combines an IP address, "
            "unencrypted HTTP and sensitive account language."
        )

    if (
            len(domain) >= 30
            and len(domain_sensitive_words) >= 2
    ):

        score += 12
        domain_risk += 15

        reasons.append(
            "The domain is long and combines "
            "multiple security-related terms."
        )

    if (
            lookalike["detected"]
            and len(found_security_words) >= 1
    ):

        score += 15
        domain_risk += 15

        reasons.append(
            "A brand-like domain pattern is combined "
            "with security or verification language."
        )

    if (
            is_shortener
            and redirect_count > 0
    ):

        score += 15
        redirect_risk += 20

        reasons.append(
            "A shortened URL was followed by a redirect, "
            "hiding the final destination."
        )

    # ========================================================
    # PRIVATE DESTINATION
    # ========================================================

    if private_resolution:

        score += 60
        security_risk += 60

        reasons.append(
            "The hostname resolves to a private or "
            "reserved network address."
        )

    # ========================================================
    # DOMAIN INTELLIGENCE
    # ========================================================

    if trusted:

        reputation = "TRUSTED"

    elif brand_impersonation:

        reputation = "BRAND IMPERSONATION"

    elif lookalike["detected"]:

        reputation = "LOOKALIKE"

    elif homoglyph["detected"]:

        reputation = "CONFUSABLE"

    elif found_words:

        reputation = "SUSPICIOUS PATTERN"

    else:

        reputation = "UNKNOWN"

    domain_intelligence = {

        "domain": domain,

        "type": (
            "IP ADDRESS"
            if ip_address
            else "DOMAIN"
        ),

        "https": (
                parsed.scheme == "https"
        ),

        "is_ip": ip_address,

        "subdomains": subdomains,

        "trusted": trusted,

        "lookalike": (
            lookalike["detected"]
        ),

        "lookalike_target": (
            lookalike["target"]
        ),

        "homoglyph": (
            homoglyph["detected"]
        ),

        "homoglyph_normalized": (
            homoglyph["normalized"]
        ),

        "brand_impersonation": (
            bool(
                brand_impersonation
            )
        ),

        "brand": (
            brand_impersonation[
                "brand"
            ]
            if brand_impersonation
            else None
        ),

        "official_domain": (
            brand_impersonation[
                "official_domain"
            ]
            if brand_impersonation
            else None
        ),

        "reputation": reputation,

        "redirects": redirect_count,

        "destination_changed": (
            destination_changed
        ),

        "final_domain": final_domain,

        "shortener": is_shortener,

        "suspicious_words": found_words,

        "security_words": found_security_words,

        "payment_words": found_payment_words,

        "encoded": "%" in url,

        "long_url": len(url) > 100,

        "at_symbol": "@" in url,

        "redirect_parameter": (
            redirect_parameter_detected
        ),

        "base_domain": (
            get_base_domain(
                domain
            )
        ),

        "final_base_domain": (
            get_base_domain(
                final_domain
            )
            if final_domain
            else ""
        ),

        "hyphens": hyphens,

        "tld": structure["tld"],

        "suspicious_tld": suspicious_tld,

        "dns_resolved": dns_resolved,

        "resolved_ips": resolved_ips[:10]
    }

    # ========================================================
    # SIGNALS
    # ========================================================

    url_signal = min(
        max(
            url_risk,
            0
        ),
        100
    )

    domain_signal = min(
        max(
            domain_risk,
            0
        ),
        100
    )

    redirect_signal = min(
        max(
            redirect_risk,
            0
        ),
        100
    )

    security_signal = min(
        max(
            security_risk,
            0
        ),
        100
    )

    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = min(
        max(
            score,
            0
        ),
        100
    )

    # Trusted domains with no serious indicators
    # should remain low risk.

    if (
            trusted
            and not brand_impersonation
            and not lookalike["detected"]
            and not homoglyph["detected"]
            and same_base_domain(
        domain,
        final_domain
    )
    ):

        strong_indicators = (
                ip_address
                or len(
            found_security_words
        ) >= 3
                or len(
            domain_sensitive_words
        ) >= 3
                or "@" in url
                or homoglyph["detected"]
                or safe_browsing.get(
            "matched"
        )
                or phishtank.get(
            "matched"
        )
        )

        if not strong_indicators:

            score = min(
                score,
                10
            )

    # ========================================================
    # VERDICT
    # ========================================================

    if score >= 60:

        verdict = "DANGER"

    elif score >= 30:

        verdict = "CAUTION"

    else:

        verdict = "SAFE"

    # ========================================================
    # DEFAULT REASON
    # ========================================================

    if not reasons:

        reasons.append(
            "No major suspicious indicators "
            "were detected."
        )

    reasons = list(
        dict.fromkeys(
            reasons
        )
    )

    reasons = reasons[:8]

    # ========================================================
    # CONFIDENCE
    # ========================================================

    available_signals = 0

    if domain:
        available_signals += 1

    available_signals += 1

    if dns_resolved:
        available_signals += 1

    if redirect_chain:
        available_signals += 1

    if rdap.get(
            "available"
    ):
        available_signals += 1

    if tls_info and tls_info.get(
            "available"
    ):
        available_signals += 1

    if page_info.get(
            "available"
    ):
        available_signals += 1

    if (
            safe_browsing.get(
                "checked"
            )
    ):
        available_signals += 1

    if (
            phishtank.get(
                "checked"
            )
    ):
        available_signals += 1

    if (
            brand_impersonation
            or lookalike["detected"]
            or homoglyph["detected"]
    ):
        available_signals += 1

    confidence = min(
        97,
        48
        + (
                available_signals
                * 5
        )
    )

    if score >= 60:
        confidence += 5

    confidence = min(
        97,
        max(
            45,
            confidence
        )
    )

    # ========================================================
    # LIVE INTELLIGENCE RESPONSE
    # ========================================================

    live_intelligence = {

        "checked": True,

        "dns": {
            "resolved": dns_resolved,
            "ips": resolved_ips[:10],
            "private_resolution": (
                private_resolution
            )
        },

        "http": {
            "status": final_status,
            "redirect_count": redirect_count,
            "final_url": final_url,
            "request_error": live["error"]
        },

        "page": page_info,

        "tls": tls_info,

        "rdap": rdap,

        "google_safe_browsing": (
            safe_browsing
        ),

        "phishtank": phishtank
    }

    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        "score": score,

        "risk_score": score,

        "verdict": verdict,

        "domain": domain,

        "final_domain": final_domain,

        "reasons": reasons,

        "redirect_chain": redirect_chain,

        "domain_intelligence":
            domain_intelligence,

        "signals": {

            "url": url_signal,

            "domain": domain_signal,

            "redirect": redirect_signal,

            "security": security_signal
        },

        "confidence": confidence,

        "query_hash": query_hash,

        "upi": None,

        "upi_risk": 0,

        "live_intelligence":
            live_intelligence
    }


# ============================================================
# QUERY HASHING
# ============================================================

def hash_query_parameters(url):

    try:

        parsed = urlparse(
            url
        )

        query = parsed.query

        if not query:
            return None

        return hashlib.sha256(
            query.encode(
                "utf-8"
            )
        ).hexdigest()

    except Exception:

        return None


# ============================================================
# UNIVERSAL ANALYSIS
# ============================================================

def analyze_input(value):

    raw = (
            value
            or ""
    ).strip()

    if not raw:

        return analyze_url(
            ""
        )

    classification = classify_payload(
        raw
    )

    qr_type = classification[
        "type"
    ]

    if qr_type == "URL":

        target = classification[
            "data"
        ].get(
            "url",
            raw
        )

        result = analyze_url(
            target
        )

        result["qr"] = {
            "type": "URL",
            "display": "Web URL",
            "raw_preview": raw[:300]
        }

        return result

    if qr_type == "UPI PAYMENT":

        result = analyze_url(
            raw
        )

        result["qr"] = {
            "type": "UPI PAYMENT",
            "display": "UPI payment request",
            "raw_preview": raw[:300]
        }

        return result

    return analyze_non_url_payload(
        raw,
        classification
    )


# ============================================================
# DATABASE PERSISTENCE ADAPTER
# ============================================================

def attach_persistence(value, result):
    """
    Persist a completed PhishLens analysis without changing the
    existing detection result.

    Database persistence is best-effort at this stage:
    a storage failure must not prevent the scanner from returning
    its security verdict.
    """
    try:

        scan_id = persist_scan(
            value,
            result
        )

        result["scan_id"] = scan_id

        result["storage"] = {
            "stored": True,
            "scan_id": scan_id
        }

    except Exception:

        app.logger.exception(
            "PhishLens persistence error"
        )

        result["storage"] = {
            "stored": False
        }

    return result
@app.errorhandler(413)
def request_too_large(error):
    """Return a controlled response when a request exceeds the size limit."""

    return jsonify({
        "error": "Request body is too large.",
        "max_bytes": app.config["MAX_CONTENT_LENGTH"],
    }), 413

# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "error":
                "No data received."
        }), 400

    value = data.get(
        "url",
        data.get(
            "payload",
            ""
        )
    )

    value = (
            value
            or ""
    ).strip()

    if not value:

        return jsonify({
            "error":
                "No URL or QR payload was provided."
        }), 400

    try:

        result = analyze_input(
            value
        )

        result = attach_persistence(
            value,
            result
        )

        return jsonify(
            result
        )

    except Exception as exc:

        app.logger.exception(
            "PhishLens analysis error"
        )

        return jsonify({
            "error":
                "Analysis failed safely.",
            "detail":
                str(exc)[:300]
        }), 500


@app.route(
    "/analyze-qr",
    methods=["POST"]
)
def analyze_qr():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "error":
                "No QR payload received."
        }), 400

    payload = (
            data.get(
                "payload",
                data.get(
                    "text",
                    ""
                )
            )
            or ""
    ).strip()

    if not payload:

        return jsonify({
            "error":
                "QR payload is empty."
        }), 400

    try:

        result = analyze_input(
            payload
        )

        result = attach_persistence(
            payload,
            result
        )

        return jsonify(
            result
        )

    except Exception as exc:

        app.logger.exception(
            "QR analysis error"
        )

        return jsonify({
            "error":
                "QR analysis failed safely.",
            "detail":
                str(exc)[:300]
        }), 500


@app.route(
    "/healthz"
)
def healthz():

    return jsonify({
        "status": "OK",
        "service": "PhishLens",
        "version": APP_VERSION,
        "live_intelligence": True,
        "rdap": True,
        "safe_browsing": bool(
            GOOGLE_SAFE_BROWSING_KEY
        ),
        "phishtank": bool(
            PHISHTANK_APP_KEY
        )
    }), 200

# ============================================================
# SERVER-SIDE HISTORY API
# ============================================================

@app.route(
    "/api/history",
    methods=["GET"]
)
def api_history():

    try:
        raw_limit = request.args.get(
            "limit",
            "50"
        )

        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            limit = 50

        limit = max(
            1,
            min(limit, 100)
        )

        return jsonify({
            "status": "OK",
            "count": len(
                get_scan_history(limit)
            ),
            "scans": get_scan_history(limit)
        }), 200

    except Exception:

        app.logger.exception(
            "History API error"
        )

        return jsonify({
            "error":
                "History could not be loaded."
        }), 500


@app.route(
    "/api/history/<scan_id>",
    methods=["GET"]
)
def api_history_scan(scan_id):

    try:
        scan = get_scan_by_id(
            scan_id
        )

        if scan is None:

            return jsonify({
                "error":
                    "Scan not found."
            }), 404

        return jsonify({
            "status": "OK",
            "scan": scan
        }), 200

    except Exception:

        app.logger.exception(
            "Single scan history API error"
        )

        return jsonify({
            "error":
                "Scan could not be loaded."
        }), 500


@app.route(
    "/api/stats",
    methods=["GET"]
)
def api_stats():

    try:

        return jsonify({
            "status": "OK",
            "stats":
                get_scan_statistics()
        }), 200

    except Exception:

        app.logger.exception(
            "Statistics API error"
        )

        return jsonify({
            "error":
                "Statistics could not be loaded."
        }), 500



# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("PHISHLENS THREAT INTELLIGENCE ENGINE")
    print("=" * 60)
    print("Version:", APP_VERSION)
    print("Live DNS: ENABLED")
    print("Redirect intelligence: ENABLED")
    print("TLS inspection: ENABLED")
    print("RDAP intelligence: ENABLED")
    print(
        "Google Safe Browsing:",
        "ENABLED"
        if GOOGLE_SAFE_BROWSING_KEY
        else "OPTIONAL / NOT CONFIGURED"
    )
    print(
        "PhishTank:",
        "ENABLED"
        if PHISHTANK_APP_KEY
        else "OPTIONAL / NOT CONFIGURED"
    )
    print("SSRF protection: ENABLED")
    print("=" * 60)
    print()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )