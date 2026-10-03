from pathlib import Path

import pytest

from mitre_mapper.intake import (
    INTAKE_SOURCE,
    IntakeError,
    intake_reference,
    parse_intake,
    resolve_domains,
)
from mitre_mapper.models import IntakeSpec

PEGASUS = """\
---
name: Pegasus for iOS
type: malware
aliases: [Pegasus]
platforms: [iOS]
references:
  - source_name: Lookout Pegasus
    url: https://info.lookout.com/pegasus.pdf
    description: "Lookout. (2016). Technical Analysis of Pegasus Spyware."
  - source_name: PegasusCitizenLab
techniques: [T1430]
groups:
  - ref: G0142
  - new:
      name: Example Actor
      description: A user-defined actor.
      techniques: [T1404]
---
Pegasus for iOS is spyware delivered through a browser zero-day chain.
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "intake.md"
    path.write_text(text, encoding="utf-8")
    return path


def test_parses_realistic_pegasus_intake(tmp_path):
    spec = parse_intake(write(tmp_path, PEGASUS))
    assert spec.name == "Pegasus for iOS" and spec.type == "malware"
    assert spec.aliases == ["Pegasus"] and spec.platforms == ["iOS"]
    assert spec.references[1].url is None
    assert spec.techniques == ["T1430"]
    assert spec.groups[0].ref == "G0142"
    assert spec.groups[1].new.techniques == ["T1404"]
    assert spec.body.startswith("Pegasus for iOS is spyware")
    assert resolve_domains(spec) == ["mobile-attack"]


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("---\nname: X\ntype: virus\n---\n", "type"),
        ("---\nname: X\n---\n", "type: Field required"),
        ("---\nname: X\ntype: tool\nbogus: 1\n---\n", "bogus"),
        ("---\nname: X\ntype: tool\ngroups:\n  - {}\n---\n", "exactly one"),
        ("---\nname: X\ntype: tool\ntechniques: [T12]\n---\n", "techniques"),
        ("---\nname: [unclosed\ntype: tool\n---\n", "cannot read"),
        ("no frontmatter at all", "no YAML frontmatter"),
        ("---\nname: X\ntype: tool\nbody: sneaky\n---\n", "body"),
    ],
)
def test_invalid_intake_raises_intake_error(tmp_path, text, fragment):
    with pytest.raises(IntakeError) as exc:
        parse_intake(write(tmp_path, text))
    assert exc.value.errors and any(fragment in e for e in exc.value.errors)


def test_missing_file_raises_intake_error(tmp_path):
    with pytest.raises(IntakeError, match="not found"):
        parse_intake(tmp_path / "nope.md")


@pytest.mark.parametrize(
    "platforms, domains, expected",
    [
        (["iOS"], None, ["mobile-attack"]),
        (["Android", "iOS"], None, ["mobile-attack"]),
        (["Windows", "Linux"], None, ["enterprise-attack"]),
        (["Field Controller/RTU/PLC/IED"], None, ["ics-attack"]),
        (["Windows", "Android"], None, ["enterprise-attack", "mobile-attack"]),
        ([], None, ["enterprise-attack"]),
        (["iOS"], ["ics-attack", "enterprise-attack", "ics-attack"], ["enterprise-attack", "ics-attack"]),
    ],
)
def test_resolve_domains(platforms, domains, expected):
    spec = IntakeSpec(name="X", type="tool", platforms=platforms, domains=domains)
    assert resolve_domains(spec) == expected


def test_intake_reference_names_file(tmp_path):
    spec = IntakeSpec(name="Pegasus for iOS", type="malware")
    ref = intake_reference(spec, tmp_path / "pegasus-ios.md")
    assert ref.source_name == INTAKE_SOURCE == "mitre-mapper intake"
    assert "pegasus-ios.md" in ref.description
