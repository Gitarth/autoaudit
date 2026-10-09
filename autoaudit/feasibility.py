"""
Path feasibility from the AST: does a reported flow pass through code that can
never execute?

Dataflow engines are path-insensitive: in

    int num = 86;
    if ((7 * 42) - num > 200) bar = "constant"; else bar = param;

they report param -> bar -> sink even though the else-branch is dead. A human
sees this at a glance; this module does the same with constant evaluation over
the enclosing function: locals assigned exactly once from a constant,
arithmetic/comparison/boolean operators, String.charAt on constants, and
if / ternary / switch branch selection. Anything it cannot prove is left alone,
so it only ever removes provably infeasible flows.
"""

from __future__ import annotations

from dataclasses import dataclass

from .alerts import Alert
from .codeindex import CodeIndex, Parsed, ancestors, enclosing_function, node_at_line, walk

VERSION = "feasibility-v2"
UNKNOWN = object()

INT = {
    "decimal_integer_literal",
    "hex_integer_literal",
    "octal_integer_literal",
    "binary_integer_literal",
    "integer",
    "number",
    "int_literal",
    "integer_literal",
}
STRING = {"string_literal", "string", "interpreted_string_literal", "raw_string_literal", "encapsed_string"}
CHAR = {"character_literal"}
TRUE, FALSE = {"true", "True"}, {"false", "False"}
PAREN = {"parenthesized_expression"}
BINARY = {"binary_expression", "binary_operator", "boolean_operator"}
UNARY = {"unary_expression", "unary_operator", "not_operator", "prefix_unary_expression"}
IFS = {"if_statement", "ternary_expression", "conditional_expression"}
SWITCHES = {"switch_expression", "switch_statement"}
DECLARATORS = {"variable_declarator"}
ASSIGNMENTS = {
    "assignment_expression",
    "assignment",
    "augmented_assignment",
    "augmented_assignment_expression",
    "assignment_statement",
    "short_var_declaration",
    "compound_assignment_expr",
}
UPDATES = {"update_expression", "inc_statement", "dec_statement", "postfix_unary_expression"}
EXITS = {"break_statement", "return_statement", "throw_statement", "continue_statement", "yield_statement"}
TRUNCATING_DIVISION = {"java", "csharp", "go"}


@dataclass
class DeadCode:
    step: int | None  # flow step number (1-based), None for the sink itself
    path: str
    line: int
    reason: str


# ------------------------------------------------------------------ constants
def _string_value(p: Parsed, node) -> str | object:
    raw = p.text(node)
    if raw[:1] in "\"'`" and raw[-1:] == raw[:1] and "\\" not in raw and "${" not in raw:
        return raw[1:-1]
    return UNKNOWN


def _targets(p: Parsed, fn) -> dict[str, list]:
    """identifier -> list of value nodes (None for non-constant writes like x++ or x += 1)."""
    writes: dict[str, list] = {}
    for n in walk(fn):
        if n.type in DECLARATORS:
            name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and name.type == "identifier":
                writes.setdefault(p.text(name), []).append(value)
        elif n.type in ASSIGNMENTS:
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is None:
                continue
            if left.type == "expression_list" and left.named_child_count == 1:
                left = left.named_children[0]
                right = (
                    right.named_children[0] if right is not None and right.named_child_count == 1 else None
                )
            if left.type == "identifier":
                simple = n.type in (
                    "assignment",
                    "assignment_expression",
                    "short_var_declaration",
                    "assignment_statement",
                ) and "=" == _operator(p, n, default="=")
                writes.setdefault(p.text(left), []).append(right if simple else None)
        elif n.type in UPDATES:
            for c in n.named_children:
                if c.type == "identifier":
                    writes.setdefault(p.text(c), []).append(None)
    return writes


def _operator(p: Parsed, node, default=None) -> str | None:
    op = node.child_by_field_name("operator")
    if op is not None:
        return p.text(op)
    for c in node.children:
        if not c.is_named:
            return p.text(c)
    return default


def constants(p: Parsed, fn) -> dict:
    env: dict = {}
    writes = _targets(p, fn)
    # resolve in a few passes so `int a = 3; int b = a * 2;` works
    for _ in range(3):
        for name, values in writes.items():
            if name in env or len(values) != 1 or values[0] is None:
                continue
            v = evaluate(p, values[0], env)
            if v is not UNKNOWN:
                env[name] = v
    return env


def evaluate(p: Parsed, n, env: dict):
    if n is None:
        return UNKNOWN
    t = n.type
    if t in INT:
        text = p.text(n).rstrip("lL").replace("_", "")
        try:
            return int(text, 0)
        except ValueError:
            return UNKNOWN
    if t in TRUE or (t == "boolean_literal" and p.text(n) == "true"):
        return True
    if t in FALSE or (t == "boolean_literal" and p.text(n) == "false"):
        return False
    if t in STRING:
        return _string_value(p, n)
    if t in CHAR:
        raw = p.text(n)
        return raw[1] if len(raw) == 3 else UNKNOWN
    if t == "identifier":
        return env.get(p.text(n), UNKNOWN)
    if t in PAREN:
        inner = [c for c in n.named_children if c.type not in ("comment",)]
        return evaluate(p, inner[0], env) if len(inner) == 1 else UNKNOWN
    if t in UNARY:
        operand = (
            n.child_by_field_name("operand")
            or n.child_by_field_name("argument")
            or (n.named_children[-1] if n.named_children else None)
        )
        v, op = evaluate(p, operand, env), _operator(p, n)
        if v is UNKNOWN:
            return UNKNOWN
        if op in ("!", "not") and isinstance(v, bool):
            return not v
        if op == "-" and isinstance(v, int) and not isinstance(v, bool):
            return -v
        return UNKNOWN
    if t in BINARY:
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        return _binary(p, _operator(p, n), evaluate(p, left, env), evaluate(p, right, env))
    if t == "comparison_operator" and n.named_child_count == 2:  # python: a < b
        a, b = n.named_children
        op = p.text(n)[a.end_byte - n.start_byte : b.start_byte - n.start_byte].strip()
        return _binary(p, op, evaluate(p, a, env), evaluate(p, b, env))
    if t in ("method_invocation", "call_expression"):
        return _call(p, n, env)
    return UNKNOWN


def _binary(p: Parsed, op, a, b):
    if a is UNKNOWN or b is UNKNOWN or op is None:
        return UNKNOWN
    ints = all(isinstance(x, int) and not isinstance(x, bool) for x in (a, b))
    try:
        if op in ("&&", "and"):
            return a and b if isinstance(a, bool) and isinstance(b, bool) else UNKNOWN
        if op in ("||", "or"):
            return a or b if isinstance(a, bool) and isinstance(b, bool) else UNKNOWN
        if op in ("==", "==="):
            return a == b
        if op in ("!=", "!=="):
            return a != b
        if op in ("<", ">", "<=", ">=") and (ints or (isinstance(a, str) and isinstance(b, str))):
            return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]
        if ints:
            if op == "+":
                return a + b
            if op == "-":
                return a - b
            if op == "*":
                return a * b
            if op == "%" and b:
                return a - b * int(a / b) if p.lang in TRUNCATING_DIVISION else a % b
            if op in ("/", "//") and b:
                return int(a / b) if p.lang in TRUNCATING_DIVISION or op == "//" else UNKNOWN
        if op == "+" and isinstance(a, str) and isinstance(b, str):
            return a + b
    except (TypeError, OverflowError):
        return UNKNOWN
    return UNKNOWN


def _call(p: Parsed, n, env):
    """Constant `"ABC".charAt(1)` (Java) / `"ABC".charAt(1)` (JS)."""
    if p.lang == "java":
        obj, name, args = (n.child_by_field_name(f) for f in ("object", "name", "arguments"))
    else:
        fn = n.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return UNKNOWN
        obj, name, args = (
            fn.child_by_field_name("object"),
            fn.child_by_field_name("property"),
            n.child_by_field_name("arguments"),
        )
    if name is None or args is None or p.text(name) != "charAt" or args.named_child_count != 1:
        return UNKNOWN
    s, i = evaluate(p, obj, env), evaluate(p, args.named_children[0], env)
    if isinstance(s, str) and isinstance(i, int) and 0 <= i < len(s):
        return s[i]
    return UNKNOWN


# ------------------------------------------------------------- dead branches
def _lines(node) -> set[int]:
    return set(range(node.start_point[0] + 1, node.end_point[0] + 2)) if node is not None else set()


def _branches(n):
    """(condition, [consequence], [alternatives]) for if-like nodes in any grammar."""
    if n.type == "conditional_expression" and n.child_by_field_name("condition") is None:
        kids = n.named_children  # python: <consequence> if <condition> else <alternative>
        return (kids[1], [kids[0]], [kids[2]]) if len(kids) == 3 else (None, [], [])
    cond = n.child_by_field_name("condition")
    cons = n.child_by_field_name("consequence")
    alts = n.children_by_field_name("alternative")
    return cond, [cons] if cons is not None else [], list(alts)


def _short(p: Parsed, node, limit=80) -> str:
    text = " ".join(p.text(node).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def dead_lines(p: Parsed, fn) -> dict[int, str]:
    """line -> why it can never execute, within one function."""
    env = constants(p, fn)
    used = lambda node: ", ".join(  # noqa: E731 - tiny local helper
        f"{k} = {env[k]!r}"
        for k in sorted({p.text(x) for x in walk(node) if x.type == "identifier"})
        if k in env
    )
    dead: dict[int, str] = {}
    for n in walk(fn):
        if n.type in IFS:
            cond, cons, alts = _branches(n)
            v = evaluate(p, cond, env)
            if not isinstance(v, bool):
                continue
            live_parts, dead_parts = (cons, alts) if v else (alts, cons)
            live = _lines(cond).union(*map(_lines, live_parts)) if live_parts else _lines(cond)
            which = "else-branch" if v else "then-branch"
            given = used(cond)
            why = (
                f"in the {which} of `{_short(p, cond)}` (line {cond.start_point[0] + 1}), which is always "
                f"{str(v).lower()}" + (f" given {given}" if given else "")
            )
            for d in dead_parts:
                for line in _lines(d) - live:
                    dead.setdefault(line, why)
        elif n.type in SWITCHES:
            dead.update({k: v for k, v in _dead_switch(p, n, env).items() if k not in dead})
    return dead


def _dead_switch(p: Parsed, n, env) -> dict[int, str]:
    value_node = n.child_by_field_name("condition") or n.child_by_field_name("value")
    body = n.child_by_field_name("body")
    value = evaluate(p, value_node, env)
    if value is UNKNOWN or body is None:
        return {}
    groups = []  # (labels or None for default, node, arrow?)
    for g in body.named_children:
        if g.type in ("switch_block_statement_group", "switch_rule"):
            labels = [c for c in g.named_children if c.type == "switch_label"]
            is_default = any(p.text(lb).strip().startswith("default") for lb in labels)
            vals = [evaluate(p, e, env) for lb in labels for e in lb.named_children]
            groups.append((None if is_default else vals, g, g.type == "switch_rule"))
        elif g.type in ("switch_case", "switch_default"):  # javascript
            v = g.child_by_field_name("value")
            groups.append((None if g.type == "switch_default" else [evaluate(p, v, env)], g, False))
    if not groups or any(vals is not None and UNKNOWN in vals for vals, _, _ in groups):
        return {}
    start = next((i for i, (vals, _, _) in enumerate(groups) if vals is not None and value in vals), None)
    if start is None:
        start = next((i for i, (vals, _, _) in enumerate(groups) if vals is None), None)
    live_idx = set()
    if start is not None:
        for i in range(start, len(groups)):
            live_idx.add(i)
            _, g, arrow = groups[i]
            if arrow or any(c.type in EXITS for c in g.named_children):
                break
    live = set().union(*(_lines(groups[i][1]) for i in live_idx)) if live_idx else set()
    live |= _lines(value_node)
    why = (
        f"in a `switch ({_short(p, value_node)})` case that is never selected: the switch value is "
        f"always {value!r}"
    )
    out = {}
    for i, (_, g, _) in enumerate(groups):
        if i not in live_idx:
            for line in _lines(g) - live:
                out[line] = why
    return out


def _writes_on_line(p: Parsed, fn, line: int) -> list[tuple[str, set[str]]]:
    """(target, identifiers read) for each simple assignment/declaration starting on a line."""
    out = []
    for n in walk(fn):
        if n.start_point[0] + 1 != line:
            continue
        if n.type in DECLARATORS:
            name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
        elif n.type in ASSIGNMENTS:
            name, value = n.child_by_field_name("left"), n.child_by_field_name("right")
        else:
            continue
        if name is not None and name.type == "identifier" and value is not None:
            out.append((p.text(name), {p.text(x) for x in walk(value) if x.type == "identifier"}))
    return out


def _live_alternative(p: Parsed, fn, line: int, dead: dict[int, str]) -> bool:
    """Is a dead tainted write `V = f(x)` duplicated by a live write `V = g(x)`?
    Then the value can still reach the sink on another path the analyzer did not list."""
    writes = _writes_on_line(p, fn, line)
    if not writes:
        return False
    for target, reads in writes:
        for n in walk(fn):
            ln = n.start_point[0] + 1
            if ln == line or ln in dead:
                continue
            if n.type in DECLARATORS:
                name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            elif n.type in ASSIGNMENTS:
                name, value = n.child_by_field_name("left"), n.child_by_field_name("right")
            else:
                continue
            if name is None or value is None or p.text(name) != target:
                continue
            if reads & {p.text(x) for x in walk(value) if x.type == "identifier"}:
                return True
    return False


def _function_facts(p: Parsed, fn) -> tuple[dict[int, str], dict, dict]:
    """(dead lines, constant collection reads, constant locals) for one function."""
    from .containers import constant_reads  # local import: containers builds on this module

    env = constants(p, fn)
    dead = dead_lines(p, fn)
    return dead, {ln: r for ln, r in constant_reads(p, fn, env).items() if ln not in dead}, env


def _dead_step(steps, sink: tuple[str, int | None], index: CodeIndex, cache: dict) -> DeadCode | None:
    from .containers import live_tainted_write

    points = [(i, s.path, s.line) for i, s in enumerate(steps, 1) if s.line]
    points.append((None, *sink))
    for step, path, line in points:
        p = index.parsed(path) if line else None
        fn = enclosing_function(p, line) if p is not None else None
        if fn is None:
            continue
        key = (path, fn.start_byte)
        if key not in cache:
            cache[key] = _function_facts(p, fn)
        dead, reads, env = cache[key]
        reason = dead.get(line)
        if reason and not _live_alternative(p, fn, line, dead):
            return DeadCode(step, path, line, f"line {line} is {reason}")
        cr = reads.get(line)
        if cr is not None and not live_tainted_write(p, fn, cr, env, set(dead) | set(reads)):
            return DeadCode(
                step, path, line, f"line {line}: {cr.reason}, so `{cr.target}` is not tainted here"
            )
    return None


def infeasible(alert: Alert, index: CodeIndex) -> DeadCode | None:
    """Evidence that the alert can never happen: EVERY reported path passes through
    provably dead code. (One dead path is not enough: the analyzer may list a dead
    path while a live one exists, e.g. two switch cases assigning the same value.)
    Returns the dead step of the first path, or None if any path may be feasible."""
    cache: dict = {}
    first = None
    for steps in alert.flows or [[]]:
        dead = _dead_step(steps, (alert.path, alert.line), index, cache)
        if dead is None:
            return None
        first = first or dead
    if len(alert.flows) > 1 and first is not None:
        first.reason += f" (all {len(alert.flows)} reported paths pass through dead code)"
    return first


def guards(p: Parsed, line: int, limit: int = 6) -> list[tuple[int, str]]:
    """Conditions that enclose a line (innermost first): what a reviewer checks above a sink."""
    out = []
    for a in ancestors(node_at_line(p, line)):
        if a.type in IFS | {"while_statement", "for_statement"}:
            cond = _branches(a)[0] if a.type in IFS else a.child_by_field_name("condition")
            if cond is not None and line not in _lines(cond):
                out.append((cond.start_point[0] + 1, _short(p, cond, 120)))
        if len(out) >= limit:
            break
    return out
