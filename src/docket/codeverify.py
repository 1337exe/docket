"""Python-only static checks: is the flagged code reachable, and does attacker input reach the sink?

Deliberately conservative: name-based call graph, intra-function taint with sanitizer awareness. It answers
"is this AI claim even plausible in this code?" - it is not a replacement for CodeQL/Semgrep. Other languages
return 'unverified' (use a plugin verifier for them: see scope.external_verifiers).
"""
from __future__ import annotations

import ast
import warnings
from pathlib import Path

from .models import FAIL, PASS, UNVERIFIED

MAX_FILES, MAX_BYTES = 3000, 1_000_000
ENTRY_DECOS = {"route", "get", "post", "put", "delete", "patch", "head", "options", "api_view", "websocket", "command", "task",
               "on_event", "listener", "subscriber", "action", "periodic_task", "shared_task", "callback", "hookimpl"}
REGISTRARS = {"path", "re_path", "url", "add_url_rule", "add_route", "add_api_route", "add_resource", "register", "connect",
              "add_handler", "add_websocket_route", "mount", "include_router"}
VIEW_BASES = ("View", "APIView", "ViewSet", "Resource", "Handler", "RequestHandler", "Controller", "MethodView")
VIEW_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "dispatch", "list", "create", "retrieve", "update", "destroy"}

SINKS = {
    "sqli": ["execute", "executemany", "executescript", "raw", "extra", "text"],
    "cmdi": ["os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
             "subprocess.Popen", "subprocess.getoutput", "commands.getoutput", "run", "Popen", "check_output"],
    "path-traversal": ["open", "send_file", "read_text", "read_bytes", "FileResponse"],
    "ssrf": ["requests.get", "requests.post", "requests.put", "requests.head", "requests.request", "httpx.get", "httpx.post",
             "urlopen", "urlretrieve", "session.get", "session.post", "client.get", "client.post"],
    "deserialization": ["pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "dill.loads", "jsonpickle.decode"],
    "ssti": ["render_template_string", "Template", "from_string"],
    "xss": ["Markup", "mark_safe", "HttpResponse", "render_template_string"],
    "open-redirect": ["redirect", "HttpResponseRedirect", "RedirectResponse"],
    "code-exec": ["eval", "exec", "compile"],
}
ALIASES = {"sql-injection": "sqli", "command-injection": "cmdi", "cmd-injection": "cmdi", "rce": "code-exec", "xxe": "deserialization",
           "path": "path-traversal", "lfi": "path-traversal", "redirect": "open-redirect", "template-injection": "ssti"}
UNIVERSAL_SANITIZERS = {"int", "float", "bool", "abs", "len", "uuid.UUID", "UUID", "ipaddress.ip_address", "ip_address", "ord"}
SANITIZERS = {
    "cmdi": {"shlex.quote", "pipes.quote", "quote"},
    "path-traversal": {"os.path.basename", "basename", "secure_filename", "safe_join", "werkzeug.utils.secure_filename"},
    "xss": {"html.escape", "escape", "markupsafe.escape", "conditional_escape", "bleach.clean", "clean", "strip_tags"},
    "open-redirect": {"url_has_allowed_host_and_scheme", "is_safe_url", "is_safe_redirect"},
    "ssrf": {"is_safe_url", "validate_url", "is_allowed_url", "check_url", "validate_external_url"},
    "code-exec": {"literal_eval", "ast.literal_eval"},
    "ssti": {"escape", "html.escape"}, "sqli": set(), "deserialization": set(),
}
FIRST_ARG_ONLY = {"sqli", "path-traversal", "ssrf", "open-redirect", "ssti", "xss", "deserialization", "code-exec"}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "yaml.SafeLoader"}
_cache: dict = {}


def canon(vuln_class):
    c = (vuln_class or "").lower()
    return ALIASES.get(c, c)


def dotted(node):
    if isinstance(node, ast.Call):
        node = node.func
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):  # e.g. Path(x).read_text
        parts.append(dotted(node.func) or "")
        parts.reverse()
        return ".".join(p for p in parts if p).replace("..", ".")
    return ".".join(reversed(parts)) or None


def last(name):
    return name.rsplit(".", 1)[-1] if name else None


def name_matches(name, patterns):
    if not name:
        return False
    for p in patterns:
        if name == p or (("." in p) and name.endswith("." + p)) or (("." not in p) and last(name) == p):
            return True
    return False


def _load(target):
    key = str(Path(target).resolve())
    if key in _cache:
        return _cache[key]
    base, funcs, entries, n = Path(target).resolve(), {}, set(), 0
    view_nodes, methods, toplevel = set(), set(), set()
    for p in sorted(base.rglob("*.py")):
        try:
            p.resolve().relative_to(base)
            if p.stat().st_size > MAX_BYTES:
                continue
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                tree = ast.parse(p.read_text(errors="replace"))
        except (OSError, ValueError, SyntaxError, RecursionError):
            continue
        n += 1
        if n > MAX_FILES:
            break
        rel = str(p.relative_to(base))
        scripts = [t for t in tree.body if not isinstance(t, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        for cd in (t for t in tree.body if isinstance(t, ast.ClassDef)):  # class bodies run at import time too (e.g. attr = staticmethod(helper))
            scripts += [t for t in cd.body if not isinstance(t, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for top in scripts:  # script code (including `if __name__ == "__main__":`) runs when the file is executed: its references are entrypoints
            if True:
                for c in ast.walk(top):
                    if isinstance(c, ast.Call) and last(dotted(c)):
                        toplevel.add(last(dotted(c)))
                    elif isinstance(c, ast.Name) and isinstance(c.ctx, ast.Load):
                        toplevel.add(c.id)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods.add(item.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if id(node) in view_nodes:
                    continue
                funcs.setdefault(node.name, []).append((rel, node))
                if any(last(dotted(d)) in ENTRY_DECOS for d in node.decorator_list):
                    entries.add(node.name)
            elif isinstance(node, ast.ClassDef):
                if any((last(dotted(b)) or "").endswith(VIEW_BASES) for b in node.bases):
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in VIEW_METHODS:
                            view_nodes.add(id(item))
                            entries.add(item.name + "@" + node.name)
                            funcs.setdefault(item.name + "@" + node.name, []).append((rel, item))
            elif isinstance(node, ast.Call) and last(dotted(node)) in REGISTRARS:
                for a in list(node.args) + [k.value for k in node.keywords]:
                    d = dotted(a)
                    if d and isinstance(a, (ast.Name, ast.Attribute)):
                        entries.add(last(d))
    entries |= {t for t in toplevel if t in funcs}
    _cache[key] = (funcs, entries, methods)
    return _cache[key]


def clear_cache():
    _cache.clear()


def _find(funcs, fn):
    if fn in funcs:
        return fn
    hits = [k for k in funcs if k.split("@")[0] == fn]  # method on a view class
    return hits[0] if hits else None


def entrypoint_reaches(a, target):
    if not target:
        return UNVERIFIED, "no --target directory"
    funcs, entries, methods = _load(target)
    fn = _find(funcs, a.get("function", ""))
    if not fn:
        return FAIL, f"function '{a.get('function')}' is not defined anywhere in the target"
    ent = {e for e in entries if e in funcs or _find(funcs, e)}
    ent = {_find(funcs, e) or e for e in ent}
    if a.get("entry_decorators"):
        ds = set(a["entry_decorators"])
        ent = {name for name, defs in funcs.items() for _, nd in defs if any(last(dotted(d)) in ds for d in nd.decorator_list)}
    if not ent:
        return UNVERIFIED, "no framework entrypoints recognised (Flask/FastAPI/Django/DRF/Tornado-style routes are understood)"
    graph = {}
    for name, defs in funcs.items():
        out = set()
        for _, nd in defs:
            for c in ast.walk(nd):  # any reference counts (callbacks, registrations), not only direct calls
                callee = c.id if isinstance(c, ast.Name) else c.attr if isinstance(c, ast.Attribute) else None
                if callee:
                    out |= {k for k in funcs if k == callee or k.split("@")[0] == callee and "@" not in callee}
        graph[name] = out
    parent, queue = {e: None for e in ent}, list(ent)
    while queue:
        cur = queue.pop(0)
        if cur == fn:
            chain = []
            while cur:
                chain.append(cur)
                cur = parent[cur]
            return PASS, "reachable: " + " -> ".join(reversed(chain))
        for nxt in graph.get(cur, ()):
            if nxt not in parent:
                parent[nxt] = cur
                queue.append(nxt)
    short = fn.split("@")[0]
    if short in methods or (short.startswith("__") and short.endswith("__")):
        return UNVERIFIED, (f"'{short}' is a method or dunder: frameworks and subclasses call those dynamically, so "
                            "'nothing calls it' cannot be concluded from names")
    return FAIL, f"no entrypoint ever calls '{short}' (dead code or internal helper)"


def _tainted(node, tainted, sanitizers):
    """Is this expression derived from attacker input without passing through a sanitizer?"""
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Call):
        if name_matches(dotted(node), sanitizers | UNIVERSAL_SANITIZERS):
            return False
    return any(_tainted(c, tainted, sanitizers) for c in ast.iter_child_nodes(node))


def _sink_safe(cls, name, call):
    """Return a reason string if this specific call is safe by construction, else None."""
    pos = call.args
    if cls == "sqli" and len(pos) >= 2 and isinstance(pos[0], ast.Constant) and isinstance(pos[0].value, str):
        return "parameterized query (values bound separately from the SQL text)"
    if cls == "cmdi" and last(name) in {"run", "call", "check_call", "check_output", "Popen"}:
        shell = next((k.value for k in call.keywords if k.arg == "shell"), None)
        if not (isinstance(shell, ast.Constant) and shell.value is True):
            if pos and isinstance(pos[0], (ast.List, ast.Tuple)):
                return "argument list without shell=True (no shell to inject into)"
    if cls == "deserialization" and last(name) == "load" and "yaml" in (name or ""):
        ld = next((k.value for k in call.keywords if k.arg == "Loader"), None)
        if ld is not None and name_matches(dotted(ld), SAFE_YAML_LOADERS):
            return "yaml loaded with a safe loader"
    return None


def _all_clean(args, clean):
    """True if every variable used in the args was assigned from a sanitizer (function names are ignored)."""
    names, funcs_ = set(), set()
    for x in args:
        for n in ast.walk(x):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                funcs_.add(id(n.func))
            elif isinstance(n, ast.Name) and id(n) not in funcs_:
                names.add(n.id)
    return bool(names) and names <= clean


def taint_flow(a, target):
    if not target:
        return UNVERIFIED, "no --target directory"
    funcs, entries, methods = _load(target)
    fn = _find(funcs, a.get("function", ""))
    if not fn:
        return FAIL, f"function '{a.get('function')}' is not defined anywhere in the target"
    cls = canon(a.get("vuln_class", ""))
    if not cls and a.get("sink"):  # infer the class from the sink name so class-specific safety rules still apply
        first = a["sink"] if isinstance(a["sink"], str) else (a["sink"] or [""])[0]
        cls = next((c for c, lst in SINKS.items() if name_matches(first, lst)), "")
    sink = a.get("sink") or SINKS.get(cls)
    if not sink:
        return UNVERIFIED, "no sink given and vuln_class has no built-in sink list"
    sinks = [sink] if isinstance(sink, str) else list(sink)
    sanitizers = set(SANITIZERS.get(cls, set())) | set(a.get("sanitizers") or [])
    sources = set(a.get("sources") or ["request"])
    seen = {}
    for _, node in funcs[fn]:
        params = {x.arg for x in node.args.args + node.args.kwonlyargs} - {"self", "cls"}
        is_entry = fn in entries or fn.split("@")[0] in entries
        tainted = set(sources) | (params if is_entry else set())
        param_only = set(params) if not is_entry else set()
        clean = set()
        for _ in range(12):
            before = (len(tainted), len(param_only))
            for st in ast.walk(node):
                if isinstance(st, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and st.value is not None:
                    tg = st.targets if isinstance(st, ast.Assign) else [st.target]
                    names = {n.id for t in tg for n in ast.walk(t) if isinstance(n, ast.Name)}
                    if _tainted(st.value, tainted, sanitizers):
                        tainted |= names
                    elif _tainted(st.value, tainted | param_only, sanitizers):
                        param_only |= names
                    elif any(isinstance(n, ast.Call) and name_matches(dotted(n), sanitizers | UNIVERSAL_SANITIZERS) for n in ast.walk(st.value)):
                        clean |= names
                elif isinstance(st, (ast.For, ast.AsyncFor)) and _tainted(st.iter, tainted, sanitizers):
                    tainted |= {n.id for n in ast.walk(st.target) if isinstance(n, ast.Name)}
            if (len(tainted), len(param_only)) == before:
                break
        for call in (c for c in ast.walk(node) if isinstance(c, ast.Call)):
            name = dotted(call)
            if not name_matches(name, sinks):
                continue
            safe = _sink_safe(cls, name, call)
            args = list(call.args[:1]) if cls in FIRST_ARG_ONLY else list(call.args) + [k.value for k in call.keywords if k.arg != "shell"]
            if safe:
                seen.setdefault("safe", safe)
            elif any(_tainted(x, tainted, sanitizers) for x in args):
                seen["tainted"] = f"attacker-controlled data reaches {name}() in {fn.split('@')[0]}() (line {call.lineno})"
            elif any(_tainted(x, tainted | param_only, sanitizers) for x in args):
                seen.setdefault("param", f"{name}() in {fn.split('@')[0]}() receives a function parameter; the caller's data flow is not traced")
            elif not any(isinstance(n, ast.Name) for x in args for n in ast.walk(x)):
                seen.setdefault("constant", f"{name}() in {fn.split('@')[0]}() only receives constants")
            elif _all_clean(args, clean) or any(isinstance(n, ast.Call) and name_matches(dotted(n), sanitizers | UNIVERSAL_SANITIZERS) for x in args for n in ast.walk(x)):
                seen.setdefault("sanitized", f"input to {name}() passes through a sanitizer")
            else:
                seen.setdefault("unknown", f"arguments to {name}() come from sources this check cannot classify")
    if "tainted" in seen:
        return PASS, seen["tainted"]
    if not seen:
        msg = f"{fn.split('@')[0]}() never calls a {cls or 'matching'} sink ({', '.join(sinks[:4])}...)"
        if a.get("auto"):  # the class came from a scanner's guess: a different sink may be the real one
            return UNVERIFIED, msg + "; the vulnerability class was guessed from the scanner output, so this is not proof of safety"
        return FAIL, msg
    for k in ("param", "unknown"):
        if k in seen:
            return UNVERIFIED, seen[k]
    return FAIL, seen.get("safe") or seen.get("sanitized") or seen.get("constant")


def class_at_line(target, rel_file, line):
    """Which sink class is actually called on the cited line? (scanner class guesses can be wrong: eval is not cmdi)"""
    from .util import safe_join
    p = safe_join(target, rel_file)
    if p is None or p.suffix != ".py" or not p.is_file():
        return ""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(p.read_text(errors="replace"))
    except (SyntaxError, ValueError, RecursionError):
        return ""
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and getattr(n, "lineno", 0) <= line <= (getattr(n, "end_lineno", 0) or 0):
            name = dotted(n)
            for c, lst in SINKS.items():
                if name_matches(name, lst):
                    return c
    return ""


def enclosing_function(target, rel_file, line):
    """Name of the innermost function containing rel_file:line (None if module level / not Python)."""
    from .util import safe_join
    p = safe_join(target, rel_file)
    if p is None or p.suffix != ".py" or not p.is_file():
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(p.read_text(errors="replace"))
    except (SyntaxError, ValueError, RecursionError):
        return None
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= line <= (n.end_lineno or n.lineno):
            if best is None or n.lineno >= best.lineno:
                best = n
    return best.name if best else None
