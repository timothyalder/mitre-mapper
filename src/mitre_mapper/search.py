"""BM25 keyword search over active techniques, groups and software."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from rank_bm25 import BM25Okapi

from .store import DomainStore

Kind = Literal["technique", "group", "software"]
_TYPES: dict[str, tuple[str, ...]] = {
    "technique": ("attack-pattern",),
    "group": ("intrusion-set",),
    "software": ("malware", "tool"),
}
_TOKEN = re.compile(r"\w+")
_CACHE: dict[tuple[int, str], tuple[BM25Okapi, list[dict[str, Any]]]] = {}


@dataclass
class SearchHit:
    attack_id: str
    name: str
    stix_id: str
    score: float


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def _document(obj: dict[str, Any]) -> list[str]:
    aliases = [*obj.get("aliases", []), *obj.get("x_mitre_aliases", [])]
    return _tokens(" ".join([obj["name"], *aliases, obj.get("description", "")]))


def _index(store: DomainStore, kind: Kind) -> tuple[BM25Okapi, list[dict[str, Any]]]:
    key = (id(store), kind)
    if key not in _CACHE:
        objs = [o for t in _TYPES[kind] for o in store.objects(t)]
        objs = [o for o in objs if store.attack_id(o)]
        _CACHE[key] = (BM25Okapi([_document(o) for o in objs]), objs)
    return _CACHE[key]


def search(store: DomainStore, kind: Kind, query: str, k: int = 10) -> list[SearchHit]:
    """Top-``k`` active objects of ``kind`` for ``query``; zero-score hits are dropped."""
    tokens = _tokens(query)
    if not tokens or k <= 0:
        return []
    bm25, objs = _index(store, kind)
    scores = bm25.get_scores(tokens)
    ranked = sorted(range(len(objs)), key=lambda i: scores[i], reverse=True)[:k]
    return [
        SearchHit(store.attack_id(objs[i]) or "", objs[i]["name"], objs[i]["id"], float(scores[i]))
        for i in ranked
        if scores[i] > 0
    ]
