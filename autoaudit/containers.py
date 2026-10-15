"""
Precise modelling of local lists and maps: which element does a read return?

Dataflow engines treat a collection as one tainted blob, so in

    List<String> l = new ArrayList<>();
    l.add("safe"); l.add(param); l.add("moresafe");
    l.remove(0);
    bar = l.get(1);          // "moresafe": a constant

or

    map.put("keyA", "a_Value"); map.put("keyB", param);
    bar = (String) map.get("keyB");
    bar = (String) map.get("keyA");   // overwrites the tainted value with a constant

they report a flow through `bar`. A reviewer replays the operations and sees a
constant. This module does the same, and only when it is sound to do so: the
collection is created empty in the function, never escapes (only used through
known methods / subscripts), and every mutation and the read are statements of
one straight-line block that is not inside a loop or lambda. Anything else and
it says nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from .codeindex import Parsed, ancestors, walk
from .feasibility import ASSIGNMENTS, DECLARATORS, UNKNOWN, evaluate

BLOCKS = {"block", "statement_block", "constructor_body"}
BARRIERS = {
    "for_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
    "for_in_statement",
    "lambda_expression",
    "arrow_function",
    "function_expression",
    "lambda",
    "generator_expression",
    "list_comprehension",
    "dictionary_comprehension",
    "try_statement",
    "catch_clause",
    "with_statement",
    "switch_expression",
    "switch_statement",
    "labeled_statement",
    "synchronized_statement",
}
JAVA_LISTS = {"ArrayList", "LinkedList", "Vector", "CopyOnWriteArrayList"}
JAVA_MAPS = {"HashMap", "LinkedHashMap", "TreeMap", "Hashtable", "ConcurrentHashMap"}
READ_ONLY = {
    "size",
    "isEmpty",
    "contains",
    "containsKey",
    "containsValue",
    "length",
    "has",
    "count",
    "index",
    "keys",
    "values",
    "indexOf",
}
NULL = None  # value of a missing map key where the language returns null/None/undefined


@dataclass
class _Op:
    kind: str  # append | remove | put | read
    stmt: object  # statement node (direct child of the block)
    args: list
    node: object  # the call / subscript node


def _strip(n):
    while n is not None and n.type in (
        "cast_expression",
        "parenthesized_expression",
        "as_expression",
        "non_null_expression",
    ):
        n = n.child_by_field_name("value") or (n.named_children[-1] if n.named_children else None)
    return n


def _new_collection(p: Parsed, value) -> str | None:
    """'list' / 'map' if `value` creates an empty collection, else None."""
    value = _strip(value)
    if value is None:
        return None
    t = value.type
    if p.lang == "java" and t == "object_creation_expression":
        args = value.child_by_field_name("arguments")
        name = p.text(value.child_by_field_name("type")).split("<")[0].split(".")[-1]
        if args is not None and args.named_child_count == 0:
            return "list" if name in JAVA_LISTS else "map" if name in JAVA_MAPS else None
    if p.lang == "python":
        if t == "list" and value.named_child_count == 0:
            return "list"
        if t == "dictionary" and value.named_child_count == 0:
            return "map"
        if t == "call" and p.text(value) in ("list()", "dict()"):
            return "list" if p.text(value) == "list()" else "map"
    if p.lang in ("javascript", "typescript", "tsx"):
        if t == "array" and value.named_child_count == 0:
            return "list"
        if t == "new_expression" and p.text(value.child_by_field_name("constructor")) == "Map":
            args = value.child_by_field_name("arguments")
            if args is None or args.named_child_count == 0:
                return "map"
    return None


# Nodes that may sit between an operation and its statement without making the
# operation conditional or repeated.
UNCONDITIONAL = {
    "expression_statement",
    "assignment_expression",
    "assignment",
    "variable_declarator",
    "local_variable_declaration",
    "lexical_declaration",
    "variable_declaration",
    "cast_expression",
    "parenthesized_expression",
    "argument_list",
    "arguments",
    "method_invocation",
    "call",
    "call_expression",
    "return_statement",
    "expression_list",
    "as_expression",
    "non_null_expression",
    "await_expression",
}


def _statement(node, block):
    """The statement of `block` that contains `node`, if `node` runs exactly once whenever
    that statement runs; None if it is outside the block or conditional/repeated within it."""
    for a in ancestors(node):
        if a.parent == block:
            return a
        if a != node and a.type not in UNCONDITIONAL:
            return None
    return None


def _args(n) -> list:
    args = n.child_by_field_name("arguments")
    return [c for c in args.named_children if c.type != "comment"] if args is not None else []


def _classify(p: Parsed, occ, kind: str):
    """(op kind, args, node) for one use of the collection, or 'escape' / 'readonly'."""
    parent = occ.parent
    if parent is None:
        return "escape"
    # receiver of a method call: java l.add(x) / python l.append(x) / js l.push(x)
    call, method = None, None
    if (
        p.lang == "java"
        and parent.type == "method_invocation"
        and parent.child_by_field_name("object") == occ
    ):
        call, method = parent, p.text(parent.child_by_field_name("name"))
    elif parent.type in ("attribute", "member_expression") and (parent.child_by_field_name("object") == occ):
        gp = parent.parent
        if (
            gp is not None
            and gp.type in ("call", "call_expression")
            and gp.child_by_field_name("function") == parent
        ):
            prop = parent.child_by_field_name("attribute") or parent.child_by_field_name("property")
            call, method = gp, p.text(prop)
    if call is not None:
        args = _args(call)
        if method in READ_ONLY:
            return "readonly"
        if kind == "list":
            if method in ("add", "append", "push") and len(args) >= 1:
                return ("append", args, call) if not (p.lang == "java" and len(args) != 1) else "escape"
            if p.lang == "java" and method == "remove" and len(args) == 1:
                return "remove", args, call
            if p.lang == "python" and method == "pop" and len(args) <= 1:
                return "remove", args or ["last"], call
            if method == "shift" and not args:
                return "remove", ["first"], call
            if method == "pop" and not args:
                return "remove", ["last"], call
            if method == "get" and p.lang == "java" and len(args) == 1:
                return "read", args, call
        else:
            if method in ("put", "set") and len(args) == 2:
                return "put", args, call
            if method == "get" and len(args) in (1, 2):
                return "read", args, call
        return "escape"
    # subscripts: python l[i] / d[k], js a[i]
    if parent.type in ("subscript", "subscript_expression") and (
        parent.child_by_field_name("value") == occ or parent.child_by_field_name("object") == occ
    ):
        idx = parent.child_by_field_name("subscript") or parent.child_by_field_name("index")
        gp = parent.parent
        if gp is not None and gp.type in ASSIGNMENTS and gp.child_by_field_name("left") == parent:
            if kind == "map" and gp.type in ("assignment", "assignment_expression"):
                return "put", [idx, gp.child_by_field_name("right")], parent
            return "escape"
        return "read", [idx], parent
    # python len(l)
    if p.lang == "python" and parent.type == "argument_list":
        call = parent.parent
        if (
            call is not None
            and p.text(call.child_by_field_name("function")) == "len"
            and parent.named_child_count == 1
        ):
            return "readonly"
    return "escape"


def _in_barrier(node, fn) -> bool:
    for a in ancestors(node.parent):
        if a == fn:
            return False
        if a.type in BARRIERS:
            return True
    return False


def _pure_assignment(p: Parsed, stmt, read_node):
    """Target name if `stmt` is exactly `target = <read>` (casts/parens allowed)."""
    inner = stmt.named_children[0] if stmt.type == "expression_statement" and stmt.named_child_count else stmt
    candidates = []
    if inner.type in DECLARATORS:
        candidates = [inner]
    elif inner.type in ("local_variable_declaration", "lexical_declaration", "variable_declaration"):
        candidates = [c for c in inner.named_children if c.type in DECLARATORS]
    if len(candidates) == 1:
        name, value = candidates[0].child_by_field_name("name"), candidates[0].child_by_field_name("value")
    elif inner.type in ("assignment", "assignment_expression"):
        name, value = inner.child_by_field_name("left"), inner.child_by_field_name("right")
    else:
        return None
    if name is None or name.type != "identifier" or _strip(value) != read_node:
        return None
    return p.text(name)


def _replay(p: Parsed, kind: str, ops: list[_Op], read: _Op, env: dict):
    """Contents before `read`, then its result (UNKNOWN when anything is not exact)."""
    items: list = []
    table: dict = {}
    for op in ops:
        if op.stmt.start_byte >= read.stmt.start_byte:
            break
        if op.kind == "append":
            items.extend(evaluate(p, a, env) for a in op.args)
        elif op.kind == "remove":
            where = op.args[0]
            if where == "first":
                i = 0
            elif where == "last":
                i = len(items) - 1
            else:
                i = evaluate(p, where, env)
                if not isinstance(i, int) or isinstance(i, bool):
                    return UNKNOWN, None  # remove(Object) or unknown index
            if not 0 <= i < len(items):
                return UNKNOWN, None
            items.pop(i)
        elif op.kind == "put":
            key = evaluate(p, op.args[0], env)
            if key is UNKNOWN:
                return UNKNOWN, None  # an unknown key could overwrite anything
            table[key] = evaluate(p, op.args[1], env)
    if kind == "list":
        i = evaluate(p, read.args[0], env)
        if not isinstance(i, int) or isinstance(i, bool):
            return UNKNOWN, None
        if i < 0 and p.lang == "python":
            i += len(items)
        if not 0 <= i < len(items):
            return UNKNOWN, None
        return items[i], items
    key = evaluate(p, read.args[0], env)
    if key is UNKNOWN:
        return UNKNOWN, None
    if key in table:
        return table[key], table
    if read.node.type in ("subscript", "subscript_expression"):
        return UNKNOWN, None  # d[missing] raises in Python
    if len(read.args) == 2:
        return evaluate(p, read.args[1], env), table  # d.get(k, default)
    return NULL, table


@dataclass
class ConstantRead:
    line: int
    target: str
    block: object
    stmt: object
    reason: str


def constant_reads(p: Parsed, fn, env: dict) -> dict[int, ConstantRead]:
    """Lines of the form `x = <collection read>` whose result is provably a constant."""
    out: dict[int, ConstantRead] = {}
    for decl in walk(fn):
        if decl.type not in DECLARATORS and decl.type not in ("assignment", "assignment_expression"):
            continue
        name_node = decl.child_by_field_name("name") or decl.child_by_field_name("left")
        value = decl.child_by_field_name("value") or decl.child_by_field_name("right")
        kind = _new_collection(p, value) if name_node is not None and name_node.type == "identifier" else None
        if kind is None:
            continue
        name = p.text(name_node)
        block = next(
            (a.parent for a in ancestors(decl) if a.parent is not None and a.parent.type in BLOCKS), None
        )
        if block is None or _in_barrier(block, fn):
            continue
        ops, ok = [], True
        for occ in walk(fn):
            if occ.type != "identifier" or p.text(occ) != name or occ == name_node:
                continue
            c = _classify(p, occ, kind)
            if c == "readonly":
                continue
            if c == "escape":
                ok = False
                break
            op_kind, args, node = c
            stmt = _statement(node, block)
            if stmt is None:
                if op_kind == "read":
                    continue  # a read elsewhere does not affect the contents
                ok = False  # a mutation outside the straight-line block
                break
            ops.append(_Op(op_kind, stmt, args, node))
        if not ok:
            continue
        # another write to the collection variable itself would make the model wrong
        if (
            sum(
                1
                for n in walk(fn)
                if n.type in DECLARATORS | ASSIGNMENTS
                and p.text(n.child_by_field_name("name") or n.child_by_field_name("left") or n) == name
            )
            != 1
        ):
            continue
        ops.sort(key=lambda o: o.node.start_byte)
        mutations = [o for o in ops if o.kind != "read"]
        for read in (o for o in ops if o.kind == "read"):
            target = _pure_assignment(p, read.stmt, _strip(read.node))
            if target is None:
                continue
            value, contents = _replay(p, kind, mutations, read, env)
            if value is UNKNOWN:
                continue
            shown = _show(contents)
            line = read.stmt.start_point[0] + 1
            out[line] = ConstantRead(
                line,
                target,
                block,
                read.stmt,
                (
                    f"`{' '.join(p.text(read.node).split())}` always returns the constant {value!r} "
                    f"({name} holds {shown} at that point)"
                ),
            )
    return out


def _show(contents) -> str:
    def fmt(v):
        return "<non-constant>" if v is UNKNOWN else repr(v)

    if isinstance(contents, dict):
        return "{" + ", ".join(f"{k!r}: {fmt(v)}" for k, v in contents.items()) + "}"
    return "[" + ", ".join(fmt(v) for v in contents) + "]"


def live_tainted_write(p: Parsed, fn, cr: ConstantRead, env: dict, safe_lines: set[int]) -> bool:
    """Could `cr.target` hold a non-constant value from another write that is not
    immediately overwritten (killed) before the constant read?"""
    stmts = [c for c in cr.block.named_children]
    idx = stmts.index(cr.stmt) if cr.stmt in stmts else -1
    for n in walk(fn):
        if n.type not in DECLARATORS | ASSIGNMENTS:
            continue
        name = n.child_by_field_name("name") or n.child_by_field_name("left")
        value = n.child_by_field_name("value") or n.child_by_field_name("right")
        if name is None or name.type != "identifier" or p.text(name) != cr.target:
            continue
        line = n.start_point[0] + 1
        if line == cr.line or line in safe_lines:
            continue
        if value is not None and evaluate(p, value, env) is not UNKNOWN:
            continue  # a constant write cannot carry taint
        stmt = _statement(n, cr.block)
        if stmt is not None and idx >= 0 and stmt in stmts and stmts.index(stmt) < idx:
            between = stmts[stmts.index(stmt) + 1 : idx]
            reads = any(
                x.type == "identifier" and p.text(x) == cr.target and not _is_target(x)
                for s in between
                for x in walk(s)
            )
            if not reads:
                continue  # killed: overwritten by the constant read before any use
        return True
    return False


def _is_target(ident) -> bool:
    parent = ident.parent
    return parent is not None and (
        (parent.type in DECLARATORS and parent.child_by_field_name("name") == ident)
        or (
            parent.type in ASSIGNMENTS
            and parent.child_by_field_name("left") == ident
            and parent.type in ("assignment", "assignment_expression")
        )
    )
