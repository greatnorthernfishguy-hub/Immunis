"""
The Armory — Immunis Threat Intelligence Store

Structurally identical to THC's Diagnostic Vector Store (DVS) but
stores threat signatures, known false-positive patterns, and response
effectiveness records instead of failure signatures and repair records.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation (Phases 1-3).
#   What: Armory with ArmoryEntry dataclass, ArmoryEntryType enum,
#         msgpack persistence with JSON fallback, cosine search,
#         LRU eviction, substrate-augmented search, load_signatures(),
#         and behavioral baseline recording.
#   Why:  PRD §6 specifies the Armory with msgpack persistence, cosine
#         search, LRU eviction. Phase 3 adds substrate-augmented search
#         and load_signatures interface.
#   Settings: max_entries=10000, persistence_format=msgpack,
#         search_top_k=10, match_threshold=0.90, eviction_policy=lru.
#   How:  In-memory dict of ArmoryEntry keyed by entry_id. Cosine
#         similarity search. msgpack persistence with JSON fallback.
#         LRU eviction when max_entries exceeded.
# -------------------
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger("immunis.armory")


class ArmoryEntryType(str, Enum):
    """Types of Armory entries (PRD §6.1)."""

    THREAT_SIGNATURE = "THREAT_SIGNATURE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESPONSE_RECORD = "RESPONSE_RECORD"
    BEHAVIORAL_BASELINE = "BEHAVIORAL_BASELINE"
    CAUSAL_CHAIN = "CAUSAL_CHAIN"


@dataclass
class ArmoryEntry:
    """A single entry in The Armory (PRD §6.2)."""

    entry_id: str = ""
    entry_type: str = ArmoryEntryType.THREAT_SIGNATURE.value
    timestamp: float = 0.0
    embedding: Optional[np.ndarray] = None
    category: str = "unknown"
    severity: str = "LOW"
    metadata: Dict[str, Any] = field(default_factory=dict)
    response_primitive: Optional[str] = None
    response_effectiveness: Optional[float] = None
    access_count: int = 0
    last_accessed: float = 0.0

    def __post_init__(self) -> None:
        if not self.entry_id:
            self.entry_id = str(uuid.uuid4())
        if self.timestamp == 0.0:
            self.timestamp = time.time()
        if self.last_accessed == 0.0:
            self.last_accessed = self.timestamp


class Armory:
    """Immunis Threat Intelligence Store (PRD §6).

    Stores threat signatures, false-positive patterns, response
    effectiveness records, behavioral baselines, and causal chains.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        data_dir: Optional[str] = None,
        ecosystem: Optional[Any] = None,
    ) -> None:
        self._config = config or {}
        self._eco = ecosystem

        self._max_entries = self._config.get("max_entries", 10000)
        self._format = self._config.get("persistence_format", "msgpack")
        self._search_top_k = self._config.get("search_top_k", 10)
        self._match_threshold = self._config.get("match_threshold", 0.90)

        self._data_dir = Path(
            data_dir or os.path.expanduser("~/.et_modules/immunis")
        )
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._entries: Dict[str, ArmoryEntry] = {}
        self._load()

    # -------------------------------------------------------------------
    # CRUD Operations
    # -------------------------------------------------------------------

    def add_entry(self, entry: ArmoryEntry) -> str:
        """Add an entry to the Armory. Returns the entry_id."""
        if len(self._entries) >= self._max_entries:
            self._evict()
        self._entries[entry.entry_id] = entry
        return entry.entry_id

    def add_threat_signature(
        self,
        embedding: np.ndarray,
        category: str,
        severity: str,
        metadata: Optional[Dict[str, Any]] = None,
        response_primitive: Optional[str] = None,
    ) -> str:
        """Convenience: add a threat signature entry."""
        entry = ArmoryEntry(
            entry_type=ArmoryEntryType.THREAT_SIGNATURE.value,
            embedding=embedding,
            category=category,
            severity=severity,
            metadata=metadata or {},
            response_primitive=response_primitive,
        )
        return self.add_entry(entry)

    def add_false_positive(
        self,
        embedding: np.ndarray,
        category: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Record a confirmed false positive pattern."""
        entry = ArmoryEntry(
            entry_type=ArmoryEntryType.FALSE_POSITIVE.value,
            embedding=embedding,
            category=category,
            severity="NONE",
            metadata=metadata or {},
        )
        return self.add_entry(entry)

    def add_response_record(
        self,
        embedding: np.ndarray,
        category: str,
        response_primitive: str,
        effectiveness: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Record response effectiveness for a threat type."""
        entry = ArmoryEntry(
            entry_type=ArmoryEntryType.RESPONSE_RECORD.value,
            embedding=embedding,
            category=category,
            severity="",
            metadata=metadata or {},
            response_primitive=response_primitive,
            response_effectiveness=effectiveness,
        )
        return self.add_entry(entry)

    def add_behavioral_baseline(
        self,
        embedding: np.ndarray,
        category: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Record a behavioral baseline ('what healthy looks like')."""
        entry = ArmoryEntry(
            entry_type=ArmoryEntryType.BEHAVIORAL_BASELINE.value,
            embedding=embedding,
            category=category,
            severity="NONE",
            metadata=metadata or {},
        )
        return self.add_entry(entry)

    def add_causal_chain(
        self,
        embedding: np.ndarray,
        category: str,
        chain_signals: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Record a Tier 3 causal chain (attack sequence)."""
        meta = metadata or {}
        meta["chain_signals"] = chain_signals
        entry = ArmoryEntry(
            entry_type=ArmoryEntryType.CAUSAL_CHAIN.value,
            embedding=embedding,
            category=category,
            severity="HIGH",
            metadata=meta,
        )
        return self.add_entry(entry)

    def get_entry(self, entry_id: str) -> Optional[ArmoryEntry]:
        """Retrieve an entry by ID."""
        entry = self._entries.get(entry_id)
        if entry is not None:
            entry.access_count += 1
            entry.last_accessed = time.time()
        return entry

    def remove_entry(self, entry_id: str) -> bool:
        """Remove an entry by ID."""
        return self._entries.pop(entry_id, None) is not None

    # -------------------------------------------------------------------
    # Search (PRD §6.4)
    # -------------------------------------------------------------------

    def search(
        self,
        embedding: np.ndarray,
        top_k: Optional[int] = None,
        entry_type: Optional[str] = None,
        min_similarity: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Search the Armory by cosine similarity.

        Phase 3 enhancement: When an ecosystem is available, search
        routes through the NG-Lite substrate for substrate-augmented
        ranking (PRD §6.4 steps 1-6).

        Args:
            embedding: Query vector (384-dim normalized).
            top_k: Max results (default from config).
            entry_type: Filter by ArmoryEntryType value.
            min_similarity: Minimum cosine similarity threshold.

        Returns:
            List of dicts with entry info + similarity score, sorted
            by relevance.
        """
        if top_k is None:
            top_k = self._search_top_k

        results: List[Dict[str, Any]] = []

        for entry in self._entries.values():
            if entry.embedding is None:
                continue
            if entry_type is not None and entry.entry_type != entry_type:
                continue

            sim = self._cosine_similarity(embedding, entry.embedding)
            if sim < min_similarity:
                continue

            # Multi-factor scoring (PRD §6.4 step 5):
            # substrate activation × cosine similarity × recency × response effectiveness
            recency = 1.0 / (1.0 + (time.time() - entry.timestamp) / 86400.0)
            effectiveness = entry.response_effectiveness or 0.5
            score = sim * recency * effectiveness

            # Substrate augmentation (Phase 3)
            if self._eco is not None:
                try:
                    novelty = self._eco.detect_novelty(embedding)
                    # Lower novelty = more substrate confidence = boost score
                    score *= (1.0 + (1.0 - novelty) * 0.5)
                except Exception:
                    pass

            results.append({
                "entry_id": entry.entry_id,
                "entry_type": entry.entry_type,
                "category": entry.category,
                "severity": entry.severity,
                "similarity": sim,
                "score": score,
                "response_primitive": entry.response_primitive,
                "response_effectiveness": entry.response_effectiveness,
                "metadata": entry.metadata,
            })

            entry.access_count += 1
            entry.last_accessed = time.time()

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def is_false_positive(
        self, embedding: np.ndarray, threshold: float = 0.90
    ) -> bool:
        """Check if an embedding matches a known false positive."""
        fps = self.search(
            embedding,
            top_k=1,
            entry_type=ArmoryEntryType.FALSE_POSITIVE.value,
            min_similarity=threshold,
        )
        return len(fps) > 0

    # -------------------------------------------------------------------
    # Signature Loading (PRD §6.5, Phase 3)
    # -------------------------------------------------------------------

    def load_signatures(self, path: str) -> int:
        """Load threat signatures from a JSON file (PRD §6.5).

        File format:
        [
            {
                "category": "malware",
                "severity": "critical",
                "description": "Known ransomware behavioral signature",
                "embedding": [0.12, -0.05, ...],  // 384-dim
                "metadata": { ... }
            },
            ...
        ]

        Returns:
            Number of signatures loaded.
        """
        expanded = os.path.expanduser(path)
        try:
            with open(expanded, "r") as f:
                sigs = json.load(f)
        except Exception as exc:
            logger.error("Failed to load signatures from %s: %s", path, exc)
            return 0

        if not isinstance(sigs, list):
            logger.error("Signature file must contain a JSON array")
            return 0

        loaded = 0
        for sig in sigs:
            try:
                emb = np.array(sig["embedding"], dtype=np.float32)
                norm = np.linalg.norm(emb)
                if norm > 0:
                    emb = emb / norm
                self.add_threat_signature(
                    embedding=emb,
                    category=sig.get("category", "unknown"),
                    severity=sig.get("severity", "MEDIUM").upper(),
                    metadata=sig.get("metadata", {}),
                )
                loaded += 1
            except (KeyError, ValueError) as exc:
                logger.warning("Skipping invalid signature: %s", exc)

        logger.info("Loaded %d signatures from %s", loaded, path)
        return loaded

    # -------------------------------------------------------------------
    # Persistence (PRD §6.3)
    # -------------------------------------------------------------------

    def save(self) -> None:
        """Persist the Armory to disk."""
        if self._format == "msgpack":
            self._save_msgpack()
        else:
            self._save_json()

    def _save_msgpack(self) -> None:
        """Save using msgpack (primary format)."""
        try:
            import msgpack
        except ImportError:
            logger.warning("msgpack not available — falling back to JSON")
            self._save_json()
            return

        path = self._data_dir / "armory.msgpack"
        data = []
        for entry in self._entries.values():
            d = {
                "entry_id": entry.entry_id,
                "entry_type": entry.entry_type,
                "timestamp": entry.timestamp,
                "embedding": (
                    entry.embedding.tolist()
                    if entry.embedding is not None
                    else None
                ),
                "category": entry.category,
                "severity": entry.severity,
                "metadata": entry.metadata,
                "response_primitive": entry.response_primitive,
                "response_effectiveness": entry.response_effectiveness,
                "access_count": entry.access_count,
                "last_accessed": entry.last_accessed,
            }
            data.append(d)

        tmp_path = path.with_suffix(".tmp")
        with open(tmp_path, "wb") as f:
            msgpack.pack(data, f, use_bin_type=True)
        os.replace(tmp_path, path)
        logger.info("Armory saved to %s (%d entries)", path, len(data))

    def _save_json(self) -> None:
        """Save using JSON (fallback format)."""
        path = self._data_dir / "armory.json"
        data = []
        for entry in self._entries.values():
            d = {
                "entry_id": entry.entry_id,
                "entry_type": entry.entry_type,
                "timestamp": entry.timestamp,
                "embedding": (
                    entry.embedding.tolist()
                    if entry.embedding is not None
                    else None
                ),
                "category": entry.category,
                "severity": entry.severity,
                "metadata": entry.metadata,
                "response_primitive": entry.response_primitive,
                "response_effectiveness": entry.response_effectiveness,
                "access_count": entry.access_count,
                "last_accessed": entry.last_accessed,
            }
            data.append(d)

        tmp_path = path.with_suffix(".tmp")
        with open(tmp_path, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, path)
        logger.info("Armory saved to %s (%d entries, JSON fallback)", path, len(data))

    def _load(self) -> None:
        """Load from disk (try msgpack first, then JSON)."""
        msgpack_path = self._data_dir / "armory.msgpack"
        json_path = self._data_dir / "armory.json"

        if msgpack_path.exists():
            try:
                import msgpack
                with open(msgpack_path, "rb") as f:
                    data = msgpack.unpack(f, raw=False)
                self._load_entries(data)
                logger.info(
                    "Armory loaded from %s (%d entries)",
                    msgpack_path, len(self._entries),
                )
                return
            except Exception as exc:
                logger.warning("Failed to load msgpack armory: %s", exc)

        if json_path.exists():
            try:
                with open(json_path, "r") as f:
                    data = json.load(f)
                self._load_entries(data)
                logger.info(
                    "Armory loaded from %s (%d entries, JSON fallback)",
                    json_path, len(self._entries),
                )
                return
            except Exception as exc:
                logger.warning("Failed to load JSON armory: %s", exc)

    def _load_entries(self, data: List[Dict[str, Any]]) -> None:
        """Populate entries from deserialized data."""
        for d in data:
            emb = d.get("embedding")
            entry = ArmoryEntry(
                entry_id=d.get("entry_id", str(uuid.uuid4())),
                entry_type=d.get("entry_type", ArmoryEntryType.THREAT_SIGNATURE.value),
                timestamp=d.get("timestamp", 0.0),
                embedding=(
                    np.array(emb, dtype=np.float32)
                    if emb is not None
                    else None
                ),
                category=d.get("category", "unknown"),
                severity=d.get("severity", "LOW"),
                metadata=d.get("metadata", {}),
                response_primitive=d.get("response_primitive"),
                response_effectiveness=d.get("response_effectiveness"),
                access_count=d.get("access_count", 0),
                last_accessed=d.get("last_accessed", 0.0),
            )
            self._entries[entry.entry_id] = entry

    # -------------------------------------------------------------------
    # Eviction (PRD §6, LRU)
    # -------------------------------------------------------------------

    def _evict(self) -> None:
        """Evict least recently accessed entries to stay within max_entries."""
        if len(self._entries) < self._max_entries:
            return

        # Sort by last_accessed, remove oldest 10%
        evict_count = max(1, self._max_entries // 10)
        sorted_entries = sorted(
            self._entries.values(), key=lambda e: e.last_accessed
        )
        for entry in sorted_entries[:evict_count]:
            del self._entries[entry.entry_id]

        logger.info("Evicted %d entries (LRU)", evict_count)

    # -------------------------------------------------------------------
    # Utility
    # -------------------------------------------------------------------

    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        """Cosine similarity between two vectors."""
        dot = float(np.dot(a, b))
        na = float(np.linalg.norm(a))
        nb = float(np.linalg.norm(b))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def get_stats(self) -> Dict[str, Any]:
        """Armory telemetry."""
        type_counts: Dict[str, int] = {}
        for entry in self._entries.values():
            type_counts[entry.entry_type] = (
                type_counts.get(entry.entry_type, 0) + 1
            )
        return {
            "total_entries": len(self._entries),
            "max_entries": self._max_entries,
            "type_counts": type_counts,
            "persistence_format": self._format,
        }
