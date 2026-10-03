"""MCP server (FastMCP) over the deterministic core: Claude Code drives a mapping, no LangChain.

TOOL NAMES AND ARGUMENTS (read by skills/map-software/SKILL.md; keep in sync)
=============================================================================
Every tool except ``start_run`` takes ``run_id`` (returned by ``start_run``). Domain-scoped tools take
an optional ``domain`` (e.g. ``"mobile-attack"``); it may be omitted when the run has exactly one domain
and is REQUIRED when the run resolved to several (``start_run`` reports ``domains``). Tools never raise:
a failure is returned as ``{"error": "..."}``.

Run lifecycle
    start_run(intake_path: str, fetch: bool = True, evidence_dir: str | None = None)
        -> {run_id, software_name, type, domains, max_attempts, evidence: [{source_name, chars}],
            intake: {...summary...}, pinned_by_user: {...}}
        Parses the intake file (invalid -> {"error", "run_id"} and the run is closed), resolves domains,
        fetches the references as evidence (failures are logged, never fatal; ``evidence_dir`` reads only a
        frozen directory). Opens runs/<run_id>/ and logs ``run_start`` with ``surface: "mcp"``.
    submit_proposal(run_id: str, proposal: dict, domain: str | None = None)
        -> {attempt, max_attempts, attempts_left, has_errors, errors: [...], warnings: [...], info: [...],
            next: "..."}
        ``proposal`` is a MappingProposal (techniques[{technique_id, rationale, evidence[{source_name,
        quote}]}], groups[{group_id, quote, source_name}], unmatched_actors, declined, decline_rationale).
        Counts one attempt for that domain against ``max_attempts``; ``user_asserted`` is forced False
        (intake-pinned items are added by the tool). Lints it (findings carry rule_id, message, target,
        details). Resubmit a corrected proposal while ``has_errors``; when attempts run out with ERRORs the
        run is closed as ``lint_failed``.
    lint_proposal(run_id: str, proposal: dict, domain: str | None = None)
        -> {has_errors, findings}      dry run: lints without counting an attempt or recording a proposal.
    mint_delta(run_id: str)
        -> {minted | declined, terminal_state, delta_path, software_id, allocations, n_objects,
            domains, techniques, groups}
        REFUSES (run stays open, ``{"error", "blocking": {...}}``) unless every domain's latest submitted
        proposal is lint-clean (an ERROR, or no submission, blocks). Then merges user-asserted items, runs
        the final lint on the merged result (a final ERROR closes the run as ``lint_failed`` and mints
        nothing), allocates SX/GX ids, writes delta.json and closes the run (``minted``; ``declined`` if every
        domain declined).
    end_run(run_id: str, reason: str, terminal_state: "declined" | "error" = "declined")
        -> {run_id, terminal_state}    closes the run without minting; ``reason`` is logged. Always end a run
        you do not mint. A session that disconnects without ending is closed as ``abandoned`` on a later
        server start (only after 30 minutes idle).

Read-only ATT&CK / evidence tools (same behaviour and logging as the LangChain agent's)
    search_techniques(run_id, query: str, k: int = 10, domain=None)   BM25 over active techniques
    get_technique(run_id, attack_id: str, domain=None)                revoked ids redirect to the successor
    search_groups(run_id, query: str, k: int = 10, domain=None)       names, aliases, descriptions
    get_group(run_id, attack_id: str, domain=None)                    id (G0046) or name/alias ("Carbon Spider")
    search_software(run_id, query: str, k: int = 10, domain=None)
    get_software(run_id, attack_id: str, domain=None)
    get_software_techniques(run_id, attack_id: str, domain=None)      techniques ATT&CK maps for that software
    get_evidence(run_id, source_name: str, offset: int = 0, max_chars: int = 8000)
        -> {text, offset, returned_chars, total_chars, next_offset}   page with next_offset until null
    read_reference(run_id, name: "linter-rules.md" | "stix-shapes.md")

Logging: every call writes calls/<n>.json + a ``tool_call`` event (searches also ``search``), exactly like a
LangChain-driven run; proposals, lint results, group quote checks, user-asserted items, allocations, mint,
delta.json, run_end, the index row and run.md are produced by the SAME functions (``session.py``). Model
calls are invisible in MCP mode, so ``n_model_calls`` is 0 and ``judge_model`` is null; no judge runs.

Registering with Claude Code (from the repo root):
    claude mcp add mitre-mapper -- uv run --directory /abs/path/to/mitre-mapper mitre-mapper-mcp
Configuration: ``--runs-dir`` / ``MITRE_MAPPER_RUNS_DIR`` (default <repo>/runs), ``--datasets-dir`` /
``MITRE_MAPPER_DATASETS_DIR`` (default <repo>/datasets), ``--max-attempts`` (default 3).
"""

from __future__ import annotations

import argparse
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from mitre_mapper import tools as T
from mitre_mapper.runlog import close_abandoned
from mitre_mapper.session import Session, SessionError, start_session
from mitre_mapper.tools import REPO_ROOT

DEFAULT_IDLE_CLOSE_S = 30 * 60
SURFACE = "mcp"

__all__ = ["McpService", "create_server", "main"]


class McpService:
    """Holds the open sessions and the configuration; its methods back the MCP tools 1:1."""

    def __init__(
        self,
        runs_dir: Path | str,
        datasets_dir: Path | str,
        allocations_path: Path | str | None = None,
        *,
        max_attempts: int = 3,
        idle_close_s: float = DEFAULT_IDLE_CLOSE_S,
        fetch_timeout: float = 20.0,
        cache_dir: Path | str | None = None,
        use_cache: bool = True,
    ) -> None:
        self.runs_dir = Path(runs_dir)
        self.datasets_dir = Path(datasets_dir)
        self.allocations_path = Path(allocations_path) if allocations_path else None
        self.max_attempts = max_attempts
        self.idle_close_s = idle_close_s
        self.fetch_timeout = fetch_timeout
        self.cache_dir = cache_dir
        self.use_cache = use_cache
        self.sessions: dict[str, Session] = {}
        self._lock = threading.RLock()
        self.closed_at_start: list[str] = self.close_stale()

    def close_stale(self) -> list[str]:
        """Close MCP runs that never ended and have been idle > ``idle_close_s`` as ``abandoned``.

        Only ``surface == "mcp"`` runs, never one this process owns, and never one touched within
        the idle window (it may belong to another live server process).
        """
        with self._lock:
            return close_abandoned(
                self.runs_dir, min_idle_s=self.idle_close_s, surface=SURFACE, exclude=set(self.sessions)
            )

    # -- lifecycle

    def start_run(
        self, intake_path: str, fetch: bool = True, evidence_dir: str | None = None
    ) -> dict[str, Any]:
        self.close_stale()
        try:
            session, log = start_session(
                intake_path,
                runs_dir=self.runs_dir,
                datasets_dir=self.datasets_dir,
                allocations_path=self.allocations_path,
                max_attempts=self.max_attempts,
                fetch=fetch,
                evidence_dir=evidence_dir,
                use_cache=self.use_cache,
                fetch_timeout=self.fetch_timeout,
                cache_dir=self.cache_dir,
            )
        except Exception as exc:  # noqa: BLE001 - tools never raise
            return {"error": f"{type(exc).__name__}: {exc}"}
        if session is None:
            return {"error": "invalid intake; the run was closed as error", "run_id": log.run_id,
                    "terminal_state": "error"}
        with self._lock:
            self.sessions[session.run_id] = session
        spec = session.spec
        return {
            "run_id": session.run_id,
            "software_name": spec.name,
            "type": spec.type,
            "domains": session.domains,
            "max_attempts": session.max_attempts,
            "evidence": [{"source_name": n, "chars": len(t)} for n, t in sorted(session.evidence.items())],
            "references_without_evidence": sorted(
                {r.source_name for r in spec.references} - set(session.evidence)
            ),
            "intake": {
                "aliases": spec.aliases,
                "platforms": spec.platforms,
                "references": [
                    {"source_name": r.source_name, "url": r.url, "description": r.description}
                    for r in spec.references
                ],
                "prose": spec.body.strip(),
            },
            "pinned_by_user": {
                "techniques": list(spec.techniques),
                "existing_groups": [g.ref for g in spec.groups if g.ref],
                "new_groups": [g.new.name for g in spec.groups if g.new],
                "note": "These are added by the tool (never judged); do not repeat them in proposals.",
            },
        }

    def _context(
        self, run_id: str, domain: str | None, any_domain: bool = False
    ) -> T.ToolContext | dict[str, Any]:
        with self._lock:
            session = self.sessions.get(run_id)
        if session is None:
            return {"error": f"unknown run_id {run_id!r} (never started, or the server restarted; "
                    "start a new run with start_run)"}
        try:
            return session.context(domain, any_domain=any_domain)
        except SessionError as exc:
            return {"error": str(exc)}

    def call(self, fn: Callable[..., dict[str, Any]], run_id: str, domain: str | None = None,
             *, any_domain: bool = False, **args: Any) -> dict[str, Any]:
        """Resolve the run/domain context and invoke one ``tools.py`` function."""
        ctx = self._context(run_id, domain, any_domain)
        if isinstance(ctx, dict):
            return ctx
        with ctx.session.lock:
            return fn(ctx, **args)


def create_server(
    runs_dir: Path | str = REPO_ROOT / "runs",
    datasets_dir: Path | str = REPO_ROOT / "datasets",
    allocations_path: Path | str | None = None,
    *,
    max_attempts: int = 3,
    idle_close_s: float = DEFAULT_IDLE_CLOSE_S,
    service: McpService | None = None,
) -> FastMCP:
    """Build the FastMCP server (closes stale abandoned MCP runs on construction)."""
    svc = service or McpService(
        runs_dir, datasets_dir, allocations_path, max_attempts=max_attempts, idle_close_s=idle_close_s
    )
    mcp = FastMCP(
        "mitre-mapper",
        instructions=(
            "Map software to MITRE ATT&CK. Call start_run(intake_path) first; pass the returned run_id to "
            "every other tool. Finish with mint_delta or end_run. Follow skills/map-software/SKILL.md."
        ),
    )
    mcp.mitre_service = svc  # type: ignore[attr-defined]  # tests / embedding

    def tool(fn: Callable[..., Any]) -> Callable[..., Any]:
        mcp.tool(fn)
        return fn

    @tool
    def start_run(intake_path: str, fetch: bool = True, evidence_dir: str | None = None) -> dict[str, Any]:
        """Open a mapping run for an intake file. Returns run_id, domains, evidence sources, intake summary."""
        return svc.start_run(intake_path, fetch, evidence_dir)

    @tool
    def search_techniques(run_id: str, query: str, k: int = 10, domain: str | None = None) -> dict[str, Any]:
        """BM25 search over active techniques in the run's domain. Try several phrasings."""
        return svc.call(T.search_techniques, run_id, domain, query=query, k=k)

    @tool
    def get_technique(run_id: str, attack_id: str, domain: str | None = None) -> dict[str, Any]:
        """Fetch one technique by ATT&CK id (revoked ids redirect to the successor)."""
        return svc.call(T.get_technique, run_id, domain, attack_id=attack_id)

    @tool
    def search_groups(run_id: str, query: str, k: int = 10, domain: str | None = None) -> dict[str, Any]:
        """BM25 search over active groups (names, aliases, descriptions)."""
        return svc.call(T.search_groups, run_id, domain, query=query, k=k)

    @tool
    def get_group(run_id: str, attack_id: str, domain: str | None = None) -> dict[str, Any]:
        """Fetch one group by ATT&CK id (G0046) or name/alias ("Carbon Spider")."""
        return svc.call(T.get_group, run_id, domain, attack_id=attack_id)

    @tool
    def search_software(run_id: str, query: str, k: int = 10, domain: str | None = None) -> dict[str, Any]:
        """BM25 search over active malware and tools."""
        return svc.call(T.search_software, run_id, domain, query=query, k=k)

    @tool
    def get_software(run_id: str, attack_id: str, domain: str | None = None) -> dict[str, Any]:
        """Fetch one malware/tool by ATT&CK id."""
        return svc.call(T.get_software, run_id, domain, attack_id=attack_id)

    @tool
    def get_software_techniques(run_id: str, attack_id: str, domain: str | None = None) -> dict[str, Any]:
        """Techniques ATT&CK maps for an existing software id (compare similar software)."""
        return svc.call(T.get_software_techniques, run_id, domain, attack_id=attack_id)

    @tool
    def get_evidence(
        run_id: str, source_name: str, offset: int = 0, max_chars: int = T.EVIDENCE_WINDOW
    ) -> dict[str, Any]:
        """A window of fetched evidence text for a reference source_name; page with next_offset."""
        return svc.call(T.get_evidence, run_id, None, any_domain=True, source_name=source_name, offset=offset, max_chars=max_chars)

    @tool
    def read_reference(run_id: str, name: str) -> dict[str, Any]:
        """Read linter-rules.md or stix-shapes.md."""
        return svc.call(T.read_reference, run_id, None, any_domain=True, name=name)

    @tool
    def lint_proposal(run_id: str, proposal: dict[str, Any], domain: str | None = None) -> dict[str, Any]:
        """Dry-run lint of a MappingProposal (no attempt counted, nothing recorded)."""
        return svc.call(T.lint_proposal, run_id, domain, proposal=proposal)

    @tool
    def submit_proposal(run_id: str, proposal: dict[str, Any], domain: str | None = None) -> dict[str, Any]:
        """Submit a MappingProposal for a domain: counts an attempt, lints it, returns the findings."""
        if domain is None and isinstance(proposal.get("domain"), str):
            domain = proposal["domain"]  # the proposal names its domain; one fewer thing to get wrong
        return svc.call(T.submit_proposal, run_id, domain, proposal=proposal)

    @tool
    def mint_delta(run_id: str) -> dict[str, Any]:
        """Mint the delta (SX/GX ids, delta.json) and close the run. Refuses while any ERROR remains."""
        return svc.call(T.mint_delta, run_id, None, any_domain=True)

    @tool
    def end_run(run_id: str, reason: str, terminal_state: str = "declined") -> dict[str, Any]:
        """Close the run without minting (terminal_state: declined | error); reason is logged."""
        return svc.call(T.end_run, run_id, None, any_domain=True, reason=reason, terminal_state=terminal_state)

    return mcp


def main(argv: list[str] | None = None) -> None:
    """``mitre-mapper-mcp``: serve over stdio."""
    ap = argparse.ArgumentParser(prog="mitre-mapper-mcp", description="MITRE ATT&CK mapper MCP server (stdio).")
    ap.add_argument("--runs-dir", default=os.environ.get("MITRE_MAPPER_RUNS_DIR", str(REPO_ROOT / "runs")))
    ap.add_argument("--datasets-dir", default=os.environ.get("MITRE_MAPPER_DATASETS_DIR", str(REPO_ROOT / "datasets")))
    ap.add_argument("--max-attempts", type=int, default=3)
    args = ap.parse_args(argv)
    create_server(args.runs_dir, args.datasets_dir, max_attempts=args.max_attempts).run()


if __name__ == "__main__":
    main()
