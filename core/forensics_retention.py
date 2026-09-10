"""Retention for Immunis forensics snapshots.

`ForensicsSnapshot` writes one directory per signal, named `{unix_ts}_{uuid}`,
holding a `processes.json` and a `network.json` — about 60 KB a time. Nothing
ever removed them. On the VPS that reached **241,065 directories / 17 GB** in
79 days (~3,038/day, ~178 MB/day) and was the single largest non-substrate
consumer on a disk sitting at 96%.

Two properties shape the implementation:

* **The timestamp is in the name.** Age is decided by parsing the directory
  name, never by `stat()`, so pruning a quarter-million entries costs one
  `scandir` rather than a quarter-million syscalls.
* **Deletion is opt-in per name.** Only directories matching exactly
  `{digits}_{uuid}` are ever considered. Anything else in the forensics root —
  a note, a tarball, a directory a human made — is invisible to this module.
  There is a test for that, because the blast radius of a wrong regex here is
  somebody's evidence.

Pruning is amortised: the caller prunes every `prune_every` snapshots rather
than on each one, so the common path stays a single `mkdir` plus two writes.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

#: A snapshot directory: unix seconds, an underscore, then a UUID4.
#: Nothing else is eligible for deletion, ever.
SNAPSHOT_NAME = re.compile(
    r"^(\d{9,11})_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Sibling directories that hold previously-archived snapshots. Bounded by the
#: same policy — an archive that grows without limit is the same bug wearing a
#: different name.
ARCHIVE_PREFIX = "forensics_archive_"


@dataclass(frozen=True)
class RetentionPolicy:
    """How much forensic history to keep.

    `max_snapshots` is the binding constraint in practice: at the observed
    ~3,038 snapshots/day, 20,000 is a little under a week and about 1.2 GB,
    against the 17 GB that unbounded growth reached.
    """

    retain_days: int = 14
    max_snapshots: int = 20_000
    #: Prune once every N snapshots written, to keep the write path cheap.
    prune_every: int = 50

    def cutoff_ts(self, now: float) -> float:
        return now - (self.retain_days * 86_400)


@dataclass(frozen=True)
class PruneResult:
    removed: int = 0
    kept: int = 0
    bytes_freed: int = 0
    skipped_unrecognised: int = 0
    errors: int = 0

    def __add__(self, other: "PruneResult") -> "PruneResult":
        return PruneResult(
            removed=self.removed + other.removed,
            kept=self.kept + other.kept,
            bytes_freed=self.bytes_freed + other.bytes_freed,
            skipped_unrecognised=self.skipped_unrecognised + other.skipped_unrecognised,
            errors=self.errors + other.errors,
        )


def _snapshots(root: Path) -> Tuple[List[Tuple[int, Path]], int]:
    """Return [(timestamp, path)] for recognised snapshots, plus a count of
    entries deliberately left alone."""
    found: List[Tuple[int, Path]] = []
    unrecognised = 0
    try:
        with os.scandir(root) as it:
            for entry in it:
                m = SNAPSHOT_NAME.match(entry.name)
                if m is None or not entry.is_dir(follow_symlinks=False):
                    unrecognised += 1
                    continue
                found.append((int(m.group(1)), Path(entry.path)))
    except FileNotFoundError:
        return [], 0
    return found, unrecognised


def _dir_size(path: Path) -> int:
    total = 0
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def select_for_removal(
    snapshots: Iterable[Tuple[int, Path]],
    policy: RetentionPolicy,
    now: float,
) -> List[Path]:
    """Pure selection: which snapshots the policy says must go.

    Age first, then oldest-first until the count is under `max_snapshots`.
    Separated from the deleting so the decision can be tested without a
    filesystem, and reviewed without trusting the caller.
    """
    items = sorted(snapshots)  # oldest first, by embedded timestamp
    cutoff = policy.cutoff_ts(now)

    doomed = [p for ts, p in items if ts < cutoff]
    survivors = [(ts, p) for ts, p in items if ts >= cutoff]

    overflow = len(survivors) - policy.max_snapshots
    if overflow > 0:
        doomed.extend(p for _ts, p in survivors[:overflow])
    return doomed


def prune_root(
    root: Path,
    policy: RetentionPolicy,
    now: float,
    dry_run: bool = False,
) -> PruneResult:
    """Apply `policy` to one forensics root."""
    snapshots, unrecognised = _snapshots(root)
    doomed = select_for_removal(snapshots, policy, now)
    doomed_set = set(doomed)

    removed = freed = errors = 0
    for path in doomed:
        size = _dir_size(path)
        if dry_run:
            removed += 1
            freed += size
            continue
        try:
            shutil.rmtree(path)
            removed += 1
            freed += size
        except OSError:
            errors += 1
    return PruneResult(
        removed=removed,
        kept=len(snapshots) - len(doomed_set),
        bytes_freed=freed,
        skipped_unrecognised=unrecognised,
        errors=errors,
    )


def archive_roots(forensics_dir: Path) -> List[Path]:
    """Sibling `forensics_archive_*` directories, if any."""
    parent = forensics_dir.parent
    try:
        return sorted(
            p for p in parent.iterdir()
            if p.is_dir() and p.name.startswith(ARCHIVE_PREFIX)
        )
    except OSError:
        return []


def prune_forensics(
    forensics_dir: Path,
    policy: Optional[RetentionPolicy] = None,
    now: Optional[float] = None,
    include_archives: bool = True,
    dry_run: bool = False,
) -> PruneResult:
    """Bound the live forensics directory and, by default, its archives."""
    import time as _time

    policy = policy or RetentionPolicy()
    now = _time.time() if now is None else now

    result = prune_root(forensics_dir, policy, now, dry_run)
    if include_archives:
        for archive in archive_roots(forensics_dir):
            result = result + prune_root(archive, policy, now, dry_run)
    return result


def should_prune(snapshots_written: int, policy: RetentionPolicy) -> bool:
    """Amortisation gate — true once every `prune_every` writes."""
    if policy.prune_every <= 1:
        return True
    return snapshots_written % policy.prune_every == 0
