from __future__ import annotations

import json

from sqlalchemy import desc, func

from database import get_session
from models import Domain, Scan


def serialize_scan(scan: Scan) -> dict:
    """Convert one database scan into an API-safe dictionary."""

    try:
        result = json.loads(scan.result_json or "{}")
    except (TypeError, json.JSONDecodeError):
        result = {}

    return {
        "scan_id": scan.scan_id,
        "input_type": scan.input_type,
        "submitted_preview": scan.submitted_preview,
        "score": scan.score,
        "verdict": scan.verdict,
        "confidence": scan.confidence,
        "upi_risk": scan.upi_risk,
        "query_hash": scan.query_hash,
        "created_at": (
            scan.created_at.isoformat()
            if scan.created_at
            else None
        ),
        "domain": (
            scan.domain.domain
            if scan.domain is not None
            else None
        ),
        "result": result,
    }


def get_scan_history(limit: int = 50) -> list[dict]:
    """
    Return the most recent persisted scans.

    The limit is capped to prevent accidental oversized responses.
    """
    limit = max(1, min(int(limit), 100))

    session = get_session()

    try:
        scans = (
            session.query(Scan)
            .order_by(desc(Scan.created_at))
            .limit(limit)
            .all()
        )

        return [
            serialize_scan(scan)
            for scan in scans
        ]

    finally:
        session.close()


def get_scan_by_id(scan_id: str) -> dict | None:
    """Return one persisted scan by its public PhishLens ID."""

    scan_id = (scan_id or "").strip()

    if not scan_id:
        return None

    session = get_session()

    try:
        scan = (
            session.query(Scan)
            .filter(Scan.scan_id == scan_id)
            .one_or_none()
        )

        if scan is None:
            return None

        return serialize_scan(scan)

    finally:
        session.close()


def get_scan_statistics() -> dict:
    """Return aggregate statistics from the persisted scan database."""

    session = get_session()

    try:
        total_scans = (
                session.query(func.count(Scan.id))
                .scalar()
                or 0
        )

        total_threats = (
                session.query(func.count(Scan.id))
                .filter(
                    Scan.verdict.in_(
                        ["DANGER", "HIGH RISK"]
                    )
                )
                .scalar()
                or 0
        )

        safe_scans = (
                session.query(func.count(Scan.id))
                .filter(Scan.verdict == "SAFE")
                .scalar()
                or 0
        )

        caution_scans = (
                session.query(func.count(Scan.id))
                .filter(Scan.verdict == "CAUTION")
                .scalar()
                or 0
        )

        domains_tracked = (
                session.query(func.count(Domain.id))
                .scalar()
                or 0
        )

        return {
            "total_scans": int(total_scans),
            "total_threats": int(total_threats),
            "safe_scans": int(safe_scans),
            "caution_scans": int(caution_scans),
            "domains_tracked": int(domains_tracked),
        }

    finally:
        session.close()