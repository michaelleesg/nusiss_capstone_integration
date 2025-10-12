"""SQLite memory and deduplication system."""

import os
import json
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path

from sqlalchemy import (
    create_engine, Column, String, Integer, DateTime, Boolean, Text, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel

from .dedup import canonicalize_url, compute_content_hash

Base = declarative_base()


class ContentRecord(Base):
    """Content tracking table."""

    __tablename__ = "contents"

    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, nullable=False)
    canonical_url = Column(String, nullable=False)
    sha256 = Column(String(64), unique=True, nullable=False)
    mime = Column(String, nullable=True)
    title = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending")
    fetched_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    artifact_path = Column(String, nullable=True)


class IOCIndex(Base):
    """IOC deduplication index."""

    __tablename__ = "ioc_index"

    normalized = Column(String, primary_key=True)
    type = Column(String, nullable=False)  # url, domain, hash, ip


class CVEIndex(Base):
    """CVE tracking index."""

    __tablename__ = "cve_index"

    cve = Column(String, primary_key=True)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    max_severity = Column(String, nullable=True)
    patch_available = Column(Boolean, nullable=True)


class RunIndex(Base):
    """Run tracking."""

    __tablename__ = "run_index"

    id = Column(Integer, primary_key=True)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)


class MemorySystem:
    """SQLite-based memory and deduplication system."""

    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or "sqlite:///./data/cti.db"

        # Ensure data directory exists
        db_path = Path(self.database_url.replace("sqlite:///", ""))
        db_path.parent.mkdir(parents=True, exist_ok=True)

        self.engine = create_engine(self.database_url)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

    def get_session(self) -> Session:
        """Get database session."""
        return self.SessionLocal()

    def check_url_processed(self, url: str) -> Optional[Dict[str, Any]]:
        """Check if URL has been processed before (for cronjob optimization)."""
        canonical_url = canonicalize_url(url)

        with self.get_session() as session:
            existing = session.query(ContentRecord).filter_by(
                canonical_url=canonical_url
            ).first()

            if existing:
                return {
                    "already_processed": True,
                    "artifact_path": existing.artifact_path,  # May be None, that's OK
                    "url": existing.url,
                    "canonical_url": existing.canonical_url,
                    "fetched_at": existing.fetched_at,
                    "sha256": existing.sha256
                }
            return None

    def check_content_exists(self, url: str, content_hash: str) -> Optional[Dict[str, Any]]:
        """Check if content with same hash already exists."""
        canonical_url = canonicalize_url(url)

        with self.get_session() as session:
            # First check by SHA-256
            existing = session.query(ContentRecord).filter_by(sha256=content_hash).first()
            if existing and existing.artifact_path:
                return {
                    "short_circuit": True,
                    "artifact_path": existing.artifact_path,
                    "url": existing.url,
                    "canonical_url": existing.canonical_url,
                    "fetched_at": existing.fetched_at
                }

            # Check if URL exists with different hash (content changed)
            existing_url = session.query(ContentRecord).filter_by(
                canonical_url=canonical_url
            ).first()

            if existing_url and existing_url.sha256 != content_hash:
                # Content changed - need to reprocess
                session.delete(existing_url)
                session.commit()

            return None

    def store_content_record(
        self,
        url: str,
        content_hash: str,
        mime: Optional[str] = None,
        title: Optional[str] = None,
        artifact_path: Optional[str] = None
    ) -> None:
        """Store content record."""
        canonical_url = canonicalize_url(url)

        with self.get_session() as session:
            record = ContentRecord(
                url=url,
                canonical_url=canonical_url,
                sha256=content_hash,
                mime=mime,
                title=title,
                artifact_path=artifact_path,
                status="completed" if artifact_path else "pending"
            )
            session.merge(record)  # Use merge to handle duplicates
            session.commit()

    def update_artifact_path(self, content_hash: str, artifact_path: str) -> None:
        """Update artifact path for content record."""
        with self.get_session() as session:
            record = session.query(ContentRecord).filter_by(sha256=content_hash).first()
            if record:
                record.artifact_path = artifact_path
                record.status = "completed"
                session.commit()

    def load_artifact(self, artifact_path: str) -> Optional[Dict[str, Any]]:
        """Load artifact from path."""
        try:
            artifact_file = Path(artifact_path)
            if artifact_file.exists():
                with open(artifact_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    def get_ioc_index(self) -> Dict[str, List[str]]:
        """Get all indexed IOCs."""
        result = {"urls": [], "domains": [], "hashes": [], "ips": []}

        with self.get_session() as session:
            iocs = session.query(IOCIndex).all()
            for ioc in iocs:
                if ioc.type in result:
                    result[ioc.type].append(ioc.normalized)

        return result

    def update_ioc_index(self, iocs: Dict[str, List[str]]) -> None:
        """Update IOC index."""
        with self.get_session() as session:
            for ioc_type, values in iocs.items():
                for value in values:
                    index_entry = IOCIndex(normalized=value, type=ioc_type)
                    session.merge(index_entry)
            session.commit()

    def get_cve_index(self) -> Dict[str, Dict[str, Any]]:
        """Get CVE index."""
        result = {}

        with self.get_session() as session:
            cves = session.query(CVEIndex).all()
            for cve in cves:
                result[cve.cve] = {
                    "last_seen": cve.last_seen,
                    "max_severity": cve.max_severity,
                    "patch_available": cve.patch_available
                }

        return result

    def update_cve_index(self, cve_data: Dict[str, Dict[str, Any]]) -> None:
        """Update CVE index."""
        with self.get_session() as session:
            for cve, data in cve_data.items():
                index_entry = CVEIndex(
                    cve=cve,
                    last_seen=datetime.utcnow(),
                    max_severity=data.get("severity"),
                    patch_available=data.get("patch_available")
                )
                session.merge(index_entry)
            session.commit()

    def start_run(self) -> int:
        """Start a new processing run."""
        with self.get_session() as session:
            run = RunIndex(started_at=datetime.utcnow())
            session.add(run)
            session.commit()
            session.refresh(run)
            return run.id

    def finish_run(self, run_id: int) -> None:
        """Mark run as finished."""
        with self.get_session() as session:
            run = session.query(RunIndex).filter_by(id=run_id).first()
            if run:
                run.finished_at = datetime.utcnow()
                session.commit()

    def get_memory_context(self, url: str, content_hash: str) -> Dict[str, Any]:
        """Get memory context for URL processing."""
        existing = self.check_content_exists(url, content_hash)

        return {
            "existing_content": existing,
            "ioc_index": self.get_ioc_index(),
            "cve_index": self.get_cve_index(),
            "canonical_url": canonicalize_url(url)
        }


# Global memory system instance
_memory_system: Optional[MemorySystem] = None


def get_memory_system() -> MemorySystem:
    """Get global memory system instance."""
    global _memory_system
    if _memory_system is None:
        db_url = os.getenv("DATABASE_URL", "sqlite:///./data/cti.db")
        _memory_system = MemorySystem(db_url)
    return _memory_system