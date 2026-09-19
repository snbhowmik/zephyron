"""Shared builders for risk-engine tests: the real policy files as a snapshot,
and Systems."""

from __future__ import annotations

from pathlib import Path

import yaml
from qavach_core.model.system import DataClass, System
from qavach_core.policy import PolicySnapshot

ROOT = Path(__file__).parent.parent.parent
POLICY_DIR = ROOT / "config" / "policy"
DOCUMENTS = (
    "z_scenarios",
    "regulatory_deadlines",
    "scoring",
    "risk_tolerance",
    "migration_effort",
    "retention_defaults",
)


def load_documents() -> dict[str, dict]:  # type: ignore[type-arg]
    return {name: yaml.safe_load((POLICY_DIR / f"{name}.yaml").read_text()) for name in DOCUMENTS}


def real_policy() -> PolicySnapshot:
    return PolicySnapshot.from_documents(load_documents())


def make_system(
    *,
    id: str = "sys-1",
    criticality: int = 3,
    data_class: DataClass = DataClass.CONFIDENTIAL,
    retention_years: float = 7.0,
    internet_facing: bool = False,
    regimes: frozenset[str] = frozenset(),
    retention_inferred: bool = False,
) -> System:
    return System(
        id=id,
        name=id,
        owner="owner",
        criticality=criticality,
        data_classification=data_class,
        retention_years=retention_years,
        retention_inferred=retention_inferred,
        internet_facing=internet_facing,
        regulatory_regimes=regimes,
        depends_on=frozenset(),
    )
