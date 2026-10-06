from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    domain: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    reputation: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    scan_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="domain",
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    scan_id: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        index=True,
        nullable=False,
    )

    input_type: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
    )

    submitted_preview: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    domain_id: Mapped[int | None] = mapped_column(
        ForeignKey("domains.id"),
        nullable=True,
        index=True,
    )

    score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    verdict: Mapped[str] = mapped_column(
        String(16),
        index=True,
        nullable=False,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        default=0,
        nullable=False,
    )

    query_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    upi_risk: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    result_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    domain: Mapped[Domain | None] = relationship(
        back_populates="scans",
    )

    redirects: Mapped[list["Redirect"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    threat_events: Mapped[list["ThreatEvent"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    qr_scan: Mapped["QRScan | None"] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        uselist=False,
    )


class Redirect(Base):
    __tablename__ = "redirects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        index=True,
        nullable=False,
    )

    hop_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    source_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    destination_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    scan: Mapped[Scan] = relationship(
        back_populates="redirects",
    )


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        index=True,
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )

    threat_type: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )

    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    details: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    scan: Mapped[Scan] = relationship(
        back_populates="threat_events",
    )


class QRScan(Base):
    __tablename__ = "qr_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        unique=True,
        index=True,
        nullable=False,
    )

    payload_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    raw_preview: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    scan: Mapped[Scan] = relationship(
        back_populates="qr_scan",
    )