"""Classifier registry.

Adding a classifier is a two-step operation:

1. Create a module under ``tokenid/classifiers/...``.
2. Decorate a ``classify(token, ctx)`` function with ``@register(...)``.

``tokenid.classifiers.load_all()`` discovers modules with ``pkgutil`` so no
central import list has to be maintained.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .models import ClassifierContext, Confidence, TokenFinding

ClassifierFunc = Callable[[str, ClassifierContext], List[TokenFinding]]


@dataclass
class ClassifierEntry:
    name: str
    family: str
    func: ClassifierFunc
    description: str = ""
    order: int = 100


_REGISTRY: Dict[str, ClassifierEntry] = {}


def register(
    name: str,
    family: str,
    description: str = "",
    order: int = 100,
    replace: bool = False,
) -> Callable[[ClassifierFunc], ClassifierFunc]:
    """Register a classifier function under ``name``."""

    def decorator(func: ClassifierFunc) -> ClassifierFunc:
        if name in _REGISTRY and not replace:
            raise ValueError("classifier already registered: %s" % name)
        _REGISTRY[name] = ClassifierEntry(
            name=name,
            family=family,
            func=func,
            description=description,
            order=order,
        )
        return func

    return decorator


def get_classifiers() -> List[ClassifierEntry]:
    return sorted(_REGISTRY.values(), key=lambda entry: (entry.order, entry.name))


def get_classifier(name: str) -> Optional[ClassifierEntry]:
    return _REGISTRY.get(name)


def clear_registry() -> None:
    """Test helper.  Production code should not need this."""
    _REGISTRY.clear()


def run_classifiers(
    token: str, ctx: ClassifierContext
) -> List[TokenFinding]:
    """Run every registered classifier, isolating failures.

    A broken classifier must never abort analysis of untrusted input.
    """
    findings: List[TokenFinding] = []
    for entry in get_classifiers():
        try:
            result = entry.func(token, ctx) or []
        except Exception as exc:  # defensive: arbitrary input must not crash
            findings.append(
                TokenFinding(
                    token_type="classifier_error",
                    family=entry.family,
                    confidence=Confidence.LOW,
                    reasoning=[
                        "Classifier %r failed safely on this input: %s"
                        % (entry.name, exc.__class__.__name__)
                    ],
                    properties={"error": exc.__class__.__name__},
                    classifier=entry.name,
                )
            )
            continue
        for finding in result:
            if not isinstance(finding, TokenFinding):
                continue
            if not finding.classifier:
                finding.classifier = entry.name
            findings.append(finding)
    return findings
