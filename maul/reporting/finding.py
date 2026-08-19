from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    PWNED = 5
    LIKELY = 4
    POSSIBLE = 3
    HARDENED = 2
    RECON = 1

    def __lt__(self, other: "Severity") -> bool:
        return self.value < other.value

    def __le__(self, other: "Severity") -> bool:
        return self.value <= other.value

    def __gt__(self, other: "Severity") -> bool:
        return self.value > other.value

    def __ge__(self, other: "Severity") -> bool:
        return self.value >= other.value


@dataclass
class Finding:
    module: str
    check: str
    severity: Severity
    title: str
    description: str
    details: dict = field(default_factory=dict)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "check": self.check,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "details": self.details,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = dict(data)
        data["severity"] = Severity[data["severity"]]
        data.pop("remediation", None)
        return cls(**data)
