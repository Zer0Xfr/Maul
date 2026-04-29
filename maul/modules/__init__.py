from __future__ import annotations

from typing import TYPE_CHECKING

from maul.reporting.finding import Finding, Severity  # noqa: F401 — re-export for module convenience

if TYPE_CHECKING:
    from maul.core.connection import ADConnection

_REGISTRY: dict[str, type["ModuleBase"]] = {}


def register(cls: type["ModuleBase"]) -> type["ModuleBase"]:
    """Class decorator that adds a module to the global registry."""
    _REGISTRY[cls.name] = cls
    return cls


def get_module(name: str) -> type["ModuleBase"] | None:
    return _REGISTRY.get(name)


def get_all_modules() -> dict[str, type["ModuleBase"]]:
    return dict(_REGISTRY)


def get_modules(names: list[str] | None = None) -> list[type["ModuleBase"]]:
    """Return module classes for the given names, or all modules if names is None."""
    if names is None:
        return list(_REGISTRY.values())
    result = []
    for name in names:
        mod = _REGISTRY.get(name)
        if mod is None:
            raise KeyError(f"Unknown module: {name!r}. Available: {list(_REGISTRY)}")
        result.append(mod)
    return result


class ModuleBase:
    name: str = ""
    description: str = ""
    opsec_safe: bool = True  # if False, skipped with --opsec

    def __init__(self, connection: "ADConnection", options: dict | None = None) -> None:
        self.conn = connection
        self.options: dict = options or {}
        self.findings: list[Finding] = []

    def run(self) -> list[Finding]:
        """Execute all checks in this module. Return a list of Finding objects."""
        raise NotImplementedError(f"{self.__class__.__name__}.run() not implemented")

    def add_finding(self, **kwargs) -> None:
        self.findings.append(Finding(module=self.name, **kwargs))
