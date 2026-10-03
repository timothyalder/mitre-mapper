"""Parse and validate intake files (markdown with YAML frontmatter, PLAN §3.1)."""

from __future__ import annotations

from pathlib import Path

import frontmatter
import yaml
from pydantic import ValidationError

from .models import Domain, ExternalReference, IntakeSpec

INTAKE_SOURCE = "mitre-mapper intake"

_MOBILE_PLATFORMS = {"ios", "android"}
_ICS_PLATFORMS = {
    "field controller/rtu/plc/ied",
    "engineering workstation",
    "input/output server",
    "control server",
    "safety instrumented system/protection relay",
    "human-machine interface",
    "data historian",
}


class IntakeError(Exception):
    """The intake file is missing or invalid; ``errors`` lists every problem."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def parse_intake(path: Path) -> IntakeSpec:
    """Read ``path`` and return a validated spec. Raises only :class:`IntakeError`."""
    path = Path(path)
    try:
        post = frontmatter.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise IntakeError([f"intake file not found: {path}"]) from None
    except (yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
        raise IntakeError([f"cannot read intake {path}: {exc}"]) from exc
    if not isinstance(post.metadata, dict) or not post.metadata:
        raise IntakeError(["intake has no YAML frontmatter"])
    if "body" in post.metadata:
        raise IntakeError(["'body' is not a frontmatter field; write prose below the frontmatter"])
    try:
        return IntakeSpec.model_validate({**post.metadata, "body": post.content.strip()})
    except ValidationError as exc:
        raise IntakeError(
            [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]
        ) from exc


def resolve_domains(spec: IntakeSpec) -> list[Domain]:
    """Explicit ``domains``, else derived from platforms. Sorted, unique, never empty."""
    if spec.domains:
        return sorted(set(spec.domains))
    found: set[Domain] = set()
    for platform in spec.platforms:
        key = platform.strip().lower()
        if key in _MOBILE_PLATFORMS:
            found.add("mobile-attack")
        elif key in _ICS_PLATFORMS:
            found.add("ics-attack")
        else:
            found.add("enterprise-attack")
    return sorted(found) or ["enterprise-attack"]


def intake_reference(spec: IntakeSpec, path: Path) -> ExternalReference:
    """Reference that cites user-asserted items to the intake file."""
    return ExternalReference(
        source_name=INTAKE_SOURCE,
        description=f"Asserted by the user in intake file {Path(path).name} for {spec.name}.",
    )
