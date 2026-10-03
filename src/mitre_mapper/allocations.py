"""Global registry of synthetic ATT&CK ids (``SX####`` software, ``GX####`` groups).

Ids are sequential from 0001 and never reused. ``peek`` never writes (lint
previews); ``allocate`` is idempotent per STIX id and writes atomically under
an ``fcntl`` lock, the only shared-state write in the tool.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

Kind = Literal["software", "group"]
_PREFIX = {"software": "SX", "group": "GX"}
_SECTION = {"software": "software", "group": "groups"}


class Allocations:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": 1, "software": {}, "groups": {}}
        return json.loads(self.path.read_text(encoding="utf-8"))

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path.with_name(self.path.name + ".lock"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    @staticmethod
    def _existing(section: dict[str, Any], stix_id: str) -> str | None:
        return next((aid for aid, rec in section.items() if rec["stix_id"] == stix_id), None)

    @staticmethod
    def _next_id(kind: Kind, section: dict[str, Any]) -> str:
        highest = max((int(aid[2:]) for aid in section), default=0)
        return f"{_PREFIX[kind]}{highest + 1:04d}"

    def peek(self, kind: Kind, stix_id: str) -> str:
        """Existing id for ``stix_id``, else the next free id. Never writes."""
        section = self._read()[_SECTION[kind]]
        return self._existing(section, stix_id) or self._next_id(kind, section)

    def peek_many(self, kind: Kind, stix_ids: list[str]) -> dict[str, str]:
        """Like :meth:`peek` for several ids at once: unallocated ids get *consecutive*
        free ids in the given order (what ``allocate`` would hand out). Never writes."""
        section = self._read()[_SECTION[kind]]
        out: dict[str, str] = {}
        next_n = int(self._next_id(kind, section)[2:])
        for stix_id in stix_ids:
            if stix_id in out:
                continue
            existing = self._existing(section, stix_id)
            if existing:
                out[stix_id] = existing
            else:
                out[stix_id] = f"{_PREFIX[kind]}{next_n:04d}"
                next_n += 1
        return out

    def record_for(self, kind: Kind, stix_id: str) -> dict[str, Any] | None:
        """Registry record for ``stix_id`` plus its ``attack_id``, or None."""
        section = self._read()[_SECTION[kind]]
        attack_id = self._existing(section, stix_id)
        return {"attack_id": attack_id, **section[attack_id]} if attack_id else None

    def allocate(
        self,
        kind: Kind,
        stix_id: str,
        name: str,
        run_id: str,
        *,
        definition_sha256: str | None = None,
    ) -> str:
        """Idempotent per ``stix_id``; persists a new id atomically.

        ``definition_sha256`` (user-defined groups) is stored on first allocation only,
        so W005 can detect a later conflicting definition; absent for software.
        """
        with self._locked():
            registry = self._read()
            section = registry[_SECTION[kind]]
            attack_id = self._existing(section, stix_id)
            if attack_id:
                return attack_id
            attack_id = self._next_id(kind, section)
            section[attack_id] = {
                "stix_id": stix_id,
                "name": name,
                "first_run": run_id,
            }
            if definition_sha256:
                section[attack_id]["definition_sha256"] = definition_sha256
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(registry, fh, indent=2)
                    fh.write("\n")
                os.replace(tmp, self.path)
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp)
                raise
            return attack_id

    def lookup(self, attack_id: str) -> dict[str, Any] | None:
        registry = self._read()
        for section in registry["software"], registry["groups"]:
            if attack_id in section:
                return dict(section[attack_id])
        return None
