from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from database import get_session
from models import Domain, QRScan, Redirect, Scan, ThreatEvent


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_scan_id() -> str:
    """Generate a human-readable, collision-resistant PhishLens scan ID."""
    return f"PL-{uuid4().hex[:12].upper()}"


def safe_json(value) -> str:
    """Serialize analysis output without crashing on unusual values."""
    return json.dumps(
        value,
        ensure_ascii=False,
        default=str,
        separators=(",", ":"),
    )


def preview_input(value: str, limit: int = 500) -> str:
    """
    Create a storage-safe preview.

    For URLs, query strings and fragments are removed because they can
    contain tracking identifiers, tokens, or other sensitive parameters.
    """
    raw = (value or "").strip()

    if not raw:
        return ""

    try:
        parsed = urlsplit(raw)

        if parsed.scheme and parsed.netloc:
            sanitized = urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    "",
                    "",
                )
            )
            return sanitized[:limit]

    except Exception:
        pass

    return raw[:limit]


def infer_input_type(value: str, result: dict) -> str:
    """Classify the persisted scan without changing analyzer behavior."""
    if result.get("upi") is not None:
        return "UPI"

    qr = result.get("qr")

    if isinstance(qr, dict):
        qr_type = str(qr.get("type") or "").upper()

        if qr_type == "URL":
            return "QR_URL"

        return "QR"

    return "URL"


def upsert_domain(session, domain_name: str, result: dict) -> Domain | None:
    """
    Create or update the domain intelligence record for a scan.
    """
    domain_name = (domain_name or "").strip().lower()

    if not domain_name:
        return None

    domain = (
        session.query(Domain)
        .filter(Domain.domain == domain_name)
        .one_or_none()
    )

    domain_info = result.get("domain_intelligence") or {}

    if domain is None:
        domain = Domain(
            domain=domain_name,
            first_seen=utc_now(),
            last_seen=utc_now(),
            risk_score=int(result.get("risk_score", 0) or 0),
            reputation=str(
                domain_info.get("reputation") or "UNKNOWN"
            ),
            scan_count=1,
        )
        session.add(domain)

    else:
        domain.last_seen = utc_now()
        domain.risk_score = max(
            int(domain.risk_score or 0),
            int(result.get("risk_score", 0) or 0),
        )
        domain.reputation = str(
            domain_info.get("reputation")
            or domain.reputation
            or "UNKNOWN"
        )
        domain.scan_count = int(domain.scan_count or 0) + 1

    session.flush()

    return domain


def persist_redirects(session, scan: Scan, result: dict) -> None:
    """Persist the redirect chain returned by the analyzer."""
    chain = result.get("redirect_chain") or []

    if not isinstance(chain, list) or len(chain) < 2:
        return

    for hop_number in range(1, len(chain)):
        source_url = str(chain[hop_number - 1])
        destination_url = str(chain[hop_number])

        session.add(
            Redirect(
                scan_id=scan.id,
                hop_number=hop_number,
                source_url=source_url,
                destination_url=destination_url,
            )
        )


def persist_threat_events(session, scan: Scan, result: dict) -> None:
    """
    Convert important analyzer signals into normalized threat events.

    These are intentionally derived from existing PhishLens results;
    no detection rules are being changed here.
    """
    domain_info = result.get("domain_intelligence") or {}
    live = result.get("live_intelligence") or {}
    dns = live.get("dns") or {}

    events: list[tuple[str, str, float | None, str | None]] = []

    safe_browsing = live.get("google_safe_browsing") or {}

    if safe_browsing.get("matched"):
        events.append(
            (
                "google_safe_browsing",
                "unsafe_resource",
                1.0,
                "Destination matched Google Safe Browsing.",
            )
        )

    phishtank = live.get("phishtank") or {}

    if phishtank.get("matched"):
        events.append(
            (
                "phishtank",
                "verified_phishing",
                1.0,
                "Destination matched a verified PhishTank entry.",
            )
        )

    if domain_info.get("brand_impersonation"):
        events.append(
            (
                "phishlens",
                "brand_impersonation",
                None,
                str(
                    domain_info.get("brand")
                    or "Brand impersonation detected."
                ),
            )
        )

    if domain_info.get("lookalike"):
        events.append(
            (
                "phishlens",
                "lookalike_domain",
                None,
                str(
                    domain_info.get("lookalike_target")
                    or "Lookalike domain detected."
                ),
            )
        )

    if domain_info.get("homoglyph"):
        events.append(
            (
                "phishlens",
                "homoglyph",
                None,
                "Confusable/homoglyph characters detected.",
            )
        )

    if dns.get("private_resolution"):
        events.append(
            (
                "phishlens",
                "private_network_resolution",
                None,
                "Hostname resolved to a private/reserved network.",
            )
        )

    for source, threat_type, confidence, details in events:
        session.add(
            ThreatEvent(
                scan_id=scan.id,
                source=source,
                threat_type=threat_type,
                confidence=confidence,
                details=details,
            )
        )


def persist_qr_scan(session, scan: Scan, result: dict) -> None:
    """Persist normalized QR metadata when the scan contains QR analysis."""
    qr = result.get("qr")

    if not isinstance(qr, dict):
        return

    session.add(
        QRScan(
            scan_id=scan.id,
            payload_type=str(qr.get("type") or "UNKNOWN"),
            raw_preview=str(
                qr.get("raw_preview")
                or ""
            )[:500],
        )
    )


def persist_scan(
        value: str,
        result: dict,
        input_type: str | None = None,
) -> str:
    """
    Persist one completed PhishLens analysis.

    Returns the generated public scan ID.
    """
    session = get_session()

    try:
        scan_id = generate_scan_id()

        domain_name = (
                result.get("final_domain")
                or result.get("domain")
                or ""
        )

        domain = upsert_domain(
            session,
            domain_name,
            result,
        )

        submitted = preview_input(value)

        query_hash = result.get("query_hash")

        if not query_hash and value:
            # Preserve compatibility with analyzer results that don't
            # provide a query hash.
            try:
                query = urlsplit(value).query

                if query:
                    query_hash = hashlib.sha256(
                        query.encode("utf-8")
                    ).hexdigest()
            except Exception:
                query_hash = None

        scan = Scan(
            scan_id=scan_id,
            input_type=(
                    input_type
                    or infer_input_type(value, result)
            ),
            submitted_preview=submitted,
            domain_id=domain.id if domain else None,
            score=int(result.get("score", 0) or 0),
            verdict=str(result.get("verdict") or "UNKNOWN"),
            confidence=float(result.get("confidence", 0) or 0),
            query_hash=query_hash,
            upi_risk=int(result.get("upi_risk", 0) or 0),
            result_json=safe_json(result),
            created_at=utc_now(),
        )

        session.add(scan)
        session.flush()

        persist_redirects(
            session,
            scan,
            result,
        )

        persist_threat_events(
            session,
            scan,
            result,
        )

        persist_qr_scan(
            session,
            scan,
            result,
        )

        session.commit()

        return scan_id

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()