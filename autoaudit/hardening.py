"""
Mitigations that live in configuration, not on the data path.

Some vulnerabilities are decided by how an object was configured rather than
by what the tainted value passed through:

- XXE (CWE-611): an XML parser is safe for untrusted input when its factory
  disallows DOCTYPEs or disables external entities;
- SpEL injection (CWE-917): evaluating with a SimpleEvaluationContext blocks
  type references, constructors and arbitrary method calls.

A reviewer checks this by following the parser / expression back to where it
was created in the same function. This module does the same on the AST and
reports the mitigation; anything it cannot see (a factory configured in another
method, a field, a framework bean) leaves the alert alone.
"""

from __future__ import annotations

from .alerts import Alert
from .codeindex import CodeIndex, Parsed, call_name, enclosing_function, walk
from .feasibility import ASSIGNMENTS, DECLARATORS, UNKNOWN, constants, evaluate

XML_SINKS = {
    "parse",
    "build",
    "read",
    "unmarshal",
    "transform",
    "validate",
    "createXMLStreamReader",
    "createXMLEventReader",
}
SPEL_EVAL = {"getValue", "setValue", "getValueType", "getValueTypeDescriptor"}


def _receiver(p: Parsed, call):
    obj = call.child_by_field_name("object")
    if obj is None:
        f = call.child_by_field_name("function")
        obj = f.child_by_field_name("object") if f is not None else None
    return obj


def _args(call) -> list:
    args = call.child_by_field_name("arguments")
    return [a for a in args.named_children if a.type != "comment"] if args is not None else []


def _defs(p: Parsed, fn) -> dict[str, list]:
    """identifier -> right-hand sides assigned to it in the function."""
    out: dict[str, list] = {}
    for n in walk(fn):
        if n.type in DECLARATORS or n.type in ASSIGNMENTS:
            left = n.child_by_field_name("name") or n.child_by_field_name("left")
            right = n.child_by_field_name("value") or n.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                out.setdefault(p.text(left), []).append(right)
    return out


def _origins(p: Parsed, name: str, defs: dict, depth: int = 0) -> set[str]:
    """`name` plus every identifier it was derived from through method calls,
    e.g. db = dbf.newDocumentBuilder() -> {db, dbf}."""
    found = {name}
    if depth > 4:
        return found
    for rhs in defs.get(name, []):
        node = rhs
        while node is not None and node.type in ("cast_expression", "parenthesized_expression"):
            node = node.child_by_field_name("value") or (
                node.named_children[-1] if node.named_children else None
            )
        while node is not None and node.type in p.spec.calls:
            recv = _receiver(p, node)
            if recv is None:
                break
            if recv.type == "identifier":
                found |= _origins(p, p.text(recv), defs, depth + 1)
                break
            node = recv
    return found


def _value(p: Parsed, node, env) -> object:
    v = evaluate(p, node, env)
    if v is not UNKNOWN:
        return v
    text = p.text(node)
    return {"true": True, "false": False, "Boolean.TRUE": True, "Boolean.FALSE": False}.get(text, text)


def _xxe(p: Parsed, fn, line: int) -> str | None:
    calls = [
        n
        for n in walk(fn)
        if n.type in p.spec.calls and n.start_point[0] + 1 == line and (call_name(p, n) or "") in XML_SINKS
    ]
    if not calls:
        return None
    recv = _receiver(p, calls[0])
    if recv is None or recv.type != "identifier":
        return None  # chained factory calls: nothing configured
    defs, env = _defs(p, fn), constants(p, fn)
    related = _origins(p, p.text(recv), defs)
    settings: list[tuple[str, object, object]] = []
    for n in walk(fn):
        if n.type not in p.spec.calls:
            continue
        r = _receiver(p, n)
        if r is None or r.type != "identifier" or p.text(r) not in related:
            continue
        name, args = call_name(p, n), _args(n)
        if name in ("setFeature", "setProperty", "setAttribute") and len(args) == 2:
            settings.append((name, _value(p, args[0], env), _value(p, args[1], env)))
        elif name == "setExpandEntityReferences" and len(args) == 1:
            settings.append((name, None, _value(p, args[0], env)))

    def has(key: str, value) -> bool:
        return any(isinstance(k, str) and key in k and v == value for _, k, v in settings)

    if has("disallow-doctype-decl", True):
        return "the XML parser's factory disallows DOCTYPE declarations (disallow-doctype-decl = true)"
    if has("external-general-entities", False) and has("external-parameter-entities", False):
        return "the XML parser's factory disables external general and parameter entities"
    if has("ACCESS_EXTERNAL_DTD", "") and (
        has("ACCESS_EXTERNAL_SCHEMA", "") or has("ACCESS_EXTERNAL_STYLESHEET", "")
    ):
        return "the XML processor forbids external DTD and schema/stylesheet access"
    if has("SUPPORT_DTD", False) or has("supportDTD", False):
        return "the StAX XMLInputFactory has DTD support disabled"
    if has("IS_SUPPORTING_EXTERNAL_ENTITIES", False) or has("isSupportingExternalEntities", False):
        return "the StAX XMLInputFactory has external entities disabled"
    return None


def _spel(p: Parsed, fn) -> str | None:
    evals = [n for n in walk(fn) if n.type in p.spec.calls and (call_name(p, n) or "") in SPEL_EVAL]
    if not evals:
        return None
    defs = _defs(p, fn)

    def simple(arg) -> bool:
        text = p.text(arg)
        if "SimpleEvaluationContext" in text:
            return True
        return arg.type == "identifier" and any(
            "SimpleEvaluationContext" in p.text(r) for r in defs.get(text, [])
        )

    if all(any(simple(a) for a in _args(n)) for n in evals):
        return (
            "every evaluation uses a SimpleEvaluationContext "
            "(no type references, constructors or method calls)"
        )
    return None


def mitigated(alert: Alert, index: CodeIndex) -> str | None:
    """Reason the alert's sink is neutralised by configuration, or None."""
    if not alert.line or not ({"CWE-611", "CWE-917"} & set(alert.cwes)):
        return None
    p = index.parsed(alert.path)
    fn = enclosing_function(p, alert.line) if p is not None else None
    if fn is None:
        return None
    if "CWE-611" in alert.cwes:
        why = _xxe(p, fn, alert.line)
        if why:
            return why
    if "CWE-917" in alert.cwes:
        return _spel(p, fn)
    return None
