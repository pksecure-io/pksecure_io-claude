# .gitignore wordlists directory behavior
_Exported on 12/28/2025 at 15:34:05 CST from Cursor (2.2.44)_

---

**User**

Why is the @Standalone_Build/wordlists/RECOMMENDED.md file ignored from the @Standalone_Build/.gitignore  likely through the `wordlists/*` entry, but the rest of the items in the @Standalone_Build/wordlists directory are not ignored

---

**Cursor**

Plan: I’ll inspect the relevant `.gitignore` patterns (repo root and `Standalone_Build/.gitignore`), check whether there are any negate (`!`) rules or nested `.gitignore` files under `Standalone_Build/wordlists/`, and then explain exactly how Git’s ignore precedence makes `RECOMMENDED.md` ignored while other items aren’t.

Nice—your `Standalone_Build/.gitignore` really does contain only `wordlists/*`, and there are **no** nested `.gitignore` files under `Standalone_Build/wordlists/` that would “unignore” anything. Next I’ll use `git check-ignore` and `git ls-files` to confirm whether the “not ignored” items are simply **already tracked**, which would explain the behavior.

### What’s happening

- **`Standalone_Build/.gitignore` has `wordlists/*`**, and Git confirms it matches `Standalone_Build/wordlists/RECOMMENDED.md`:

```1:1:Standalone_Build/.gitignore
**/TEMP-Wordlists
**/__pycache__
**/.venv
.env
wordlists/*
```

- **But `.gitignore` only affects *untracked* files.** If a file is already in the repo (tracked/committed), Git will keep tracking it even if a later `.gitignore` pattern matches it.

### Why `RECOMMENDED.md` is ignored but the rest isn’t

- **`RECOMMENDED.md` is untracked**, so `wordlists/*` ignores it.
- **The other items you mentioned are tracked**, so they are *not* ignored (they’re already in Git’s index), even though `wordlists/*` matches them.

Concretely, in your repo:
- Tracked examples (so ignore doesn’t apply): `Standalone_Build/wordlists/README.md`, `Standalone_Build/wordlists/rockyou.txt.gz`, `Standalone_Build/wordlists/Discovery/Web-Content/big.txt`
- Untracked (so ignore applies): `Standalone_Build/wordlists/RECOMMENDED.md`

If you want `wordlists/*` to “take effect” for already-tracked files, you’d need to **remove them from the index** (e.g., `git rm --cached ...`)—but that’s a behavior change, so tell me what you want the repo policy to be and I can recommend the cleanest approach.

```plaintext
**/TEMP-Wordlists
**/__pycache__
**/.venv
.env
wordlists/*
```

---

**User**

Please recommend the cleanest approach, I do not want any of the wordlists to by sync'd to Github as they are 1.6GB in size. How can I cleanly just get the wordlist/* files ignored and not impact anything else in the repo

---

**Cursor**

Plan: I’ll (1) confirm which `Standalone_Build/wordlists/**` files are currently tracked, (2) update ignore rules to explicitly ignore the whole `wordlists/` tree, (3) remove any tracked wordlists from Git **without deleting them locally** (`git rm --cached`), and (4) add a small non-wordlists doc in `Standalone_Build/` so future clones know how to populate the folder.

Good news: the reason your wordlists still “show up” despite `wordlists/*` is that **most of `Standalone_Build/wordlists/**` is currently tracked in Git** (so ignore rules don’t apply). Next I’ll tighten the ignore pattern to only target `Standalone_Build/wordlists/`, then remove the tracked wordlists from the Git index (leaving the files on disk), and add a small doc outside that folder for future setup.

```ignore
**/TEMP-Wordlists
**/__pycache__
**/.venv
.env
# Wordlists are intentionally local-only (too large to commit).
/wordlists/
```

```ignore
Public_Github/*
shodan-mcp-server/.env
.env
**/__pycache__
**/.venv
/Standalone_Build/wordlists/
```

```markdown
# Wordlists (local-only)

This repo intentionally does **not** sync `Standalone_Build/wordlists/` to GitHub.
The folder can be ~GBs in size (SecLists + extras), and keeping it out of Git keeps
clones fast and avoids bloating history.

## Where tools expect wordlists

- `Standalone_Build/wordlists/`

Populate this directory locally on each machine.

## Suggested sources

- **SecLists** usage guide: `https://deepwiki.com/danielmiessler/SecLists/6-usage-guide`
- **Kali**: `apt install seclists`
- **Git clone (shallow)**: `git clone --depth 1 https://github.com/danielmiessler/SecLists.git`

## Notes / recommendations

- **Passwords**: `rockyou.txt` is useful but large/slow; prefer smaller targeted lists where possible.
- **Web content discovery**:
  - Quick scans: `common.txt`
  - Login pages: `Logins.fuzz.txt`
  - “Quick hits”/common vuln paths: `quickhits.txt`
- **DNS brute force**: `combined_subdomains.txt` is comprehensive; smaller `subdomains-top1million-*` lists are faster.

## Git hygiene

If you accidentally add wordlists to git again, remove them from the index (without deleting local files) using:

```bash
git rm -r --cached Standalone_Build/wordlists
```


```

Aha—there are **6,202 tracked files** under `Standalone_Build/wordlists/`, which is why `.gitignore` can’t “turn them off”. Next step is the key cleanup: remove that directory from the Git index with `git rm --cached` (keeps your local files), then verify `git status` shows the repo clean except for the intended changes.

### Cleanest approach (keeps wordlists local, doesn’t affect anything else)

#### 1) Ignore the folder at the repo root (so everyone gets it)
In the repo root `.gitignore`, keep this rule:

```1:6:.gitignore
Public_Github/*
shodan-mcp-server/.env
.env
**/__pycache__
**/.venv
/Standalone_Build/wordlists/
```

This ensures **nothing under `Standalone_Build/wordlists/` can be accidentally added** in future clones.

#### 2) Remove any already-tracked wordlists from Git *without deleting local files*
Run (once):

```bash
git rm -r --cached Standalone_Build/wordlists
```

You’re already in the good state locally now:

- `git ls-files Standalone_Build/wordlists` → **0** (not tracked)
- `git check-ignore -v Standalone_Build/wordlists/...` → **ignored**

#### 3) Commit *only* the ignore/doc changes (so you don’t accidentally commit other staged stuff)
Your working tree currently has other unrelated staged changes, so do a **path-limited commit**:

```bash
git commit -m "Ignore Standalone_Build wordlists (local-only)" -- .gitignore Standalone_Build/WORDLISTS.md
```

If you also want the per-folder ignore file committed (optional, but it matches what you were editing):

```bash
git commit -m "Ignore Standalone_Build wordlists (local-only)" -- .gitignore Standalone_Build/.gitignore Standalone_Build/WORDLISTS.md
```

#### If wordlists were ever pushed to GitHub already
Ignoring/removing won’t shrink the repo; you’d need a history rewrite (e.g., `git filter-repo`). Tell me if that happened and I’ll give you the safest exact sequence for your branching/workflow.

```plaintext
Public_Github/*
shodan-mcp-server/.env
.env
**/__pycache__
**/.venv
/Standalone_Build/wordlists/
```

```shellscript
git rm -r --cached Standalone_Build/wordlists
```

```shellscript
git commit -m "Ignore Standalone_Build wordlists (local-only)" -- .gitignore Standalone_Build/WORDLISTS.md
```

```shellscript
git commit -m "Ignore Standalone_Build wordlists (local-only)" -- .gitignore Standalone_Build/.gitignore Standalone_Build/WORDLISTS.md
```

---

**User**

How do I ignore an entire directory via .gitignore except specific files, such as the RECOMMENDED.md file in wordlists

---

**Cursor**

```plaintext
/wordlists/*
!/wordlists/RECOMMENDED.md
```

Plan: I’ll update your `.gitignore` patterns to use Git’s “ignore then unignore” (`!`) rules, making sure the parent directory isn’t excluded in a way that blocks re-inclusion. Then I’ll show the exact minimal snippet for “ignore everything in `wordlists/` except `RECOMMENDED.md`”, plus the one gotcha that trips people up.

```ignore
*** Begin Patch
*** Update File: Standalone_Build/.gitignore
@@
 .env
 # Wordlists are intentionally local-only (too large to commit).
-!/wordlists/RECOMMENDED
 /wordlists/*
+# …except this small index doc:
+!/wordlists/RECOMMENDED.md
 /logs/*
*** End Patch
```

Good catch: your `Standalone_Build/.gitignore` currently has two issues that prevent the exception from working—(1) the exception is missing `.md`, and (2) it appears **before** the ignore rule, so it gets overridden. I’ll patch it to “ignore first, then unignore the specific file.”

```ignore
**/TEMP-Wordlists
**/__pycache__
**/.venv
.env
# Wordlists are intentionally local-only (too large to commit).
/wordlists/*
# …except this small index doc:
!/wordlists/RECOMMENDED.md
/logs/*
```

```ignore
Public_Github/*
shodan-mcp-server/.env
.env
**/__pycache__
**/.venv
/Standalone_Build/wordlists/*
# Allow a small index doc to be committed even though wordlists are local-only.
!/Standalone_Build/wordlists/RECOMMENDED.md
/Standalone_Build/logs/*
```

### Ignore a whole directory **except** specific files

Put an ignore rule first, then a negate (`!`) rule after it.

For your case (ignore all of `Standalone_Build/wordlists/` but allow `RECOMMENDED.md`), this works:

```1:8:Standalone_Build/.gitignore
**/TEMP-Wordlists
**/__pycache__
**/.venv
.env
# Wordlists are intentionally local-only (too large to commit).
/wordlists/*
# …except this small index doc:
!/wordlists/RECOMMENDED.md
/logs/*
```

And (optionally, for clarity at repo root) the matching root rule:

```1:8:.gitignore
Public_Github/*
shodan-mcp-server/.env
.env
**/__pycache__
**/.venv
/Standalone_Build/wordlists/*
# Allow a small index doc to be committed even though wordlists are local-only.
!/Standalone_Build/wordlists/RECOMMENDED.md
/Standalone_Build/logs/*
```

### The one “gotcha”
- If you ignore the *directory itself* (e.g. `/wordlists/`), Git won’t descend into it, so you must also re-include the directory (`!/wordlists/`) before re-including a file inside.
- Your pattern `/wordlists/*` ignores the **contents** (not the folder), so `!/wordlists/RECOMMENDED.md` works cleanly.

### What to do now
`RECOMMENDED.md` is confirmed **not ignored** and currently untracked, so you can commit it normally:

```bash
git add Standalone_Build/wordlists/RECOMMENDED.md
```

```plaintext
**/TEMP-Wordlists
**/__pycache__
**/.venv
.env
# Wordlists are intentionally local-only (too large to commit).
/wordlists/*
# …except this small index doc:
!/wordlists/RECOMMENDED.md
/logs/*
```

```plaintext
Public_Github/*
shodan-mcp-server/.env
.env
**/__pycache__
**/.venv
/Standalone_Build/wordlists/*
# Allow a small index doc to be committed even though wordlists are local-only.
!/Standalone_Build/wordlists/RECOMMENDED.md
/Standalone_Build/logs/*
```

```shellscript
git add Standalone_Build/wordlists/RECOMMENDED.md
```

---

**User**

You had previously made changes to the port scanning tools to make any inputs/flags that are "nullable" to be optional (for example, with the `portscan.naabu_scan` tool) - can you please review all of the available tools -- one specific one `pdtm.pd_run` and make any nullable item be optional (and default to "null" if needed when running the script).

---

**Cursor**

Plan: I’ll locate where `pdtm.pd_run` (and other MCP tools) are defined, identify parameters typed as `Optional[...]` (or otherwise nullable) but still required because they lack a default, then update signatures/models so they’re truly optional (default `None`). Finally I’ll ensure the CLI wrapper treats `None` as “omit this flag” and doesn’t pass `"null"` strings.

Nice: `pdtm-mcp-server` already defines `pd_run` with `args`, `stdin_lines`, and `save` defaulting to `None`, so it *should* be optional in the schema. Next I’ll scan the rest of the servers for parameters typed nullable (`Optional[...]` / `| None`) but lacking a default, then patch both the main and `Standalone_Build/*/src` copies to keep behavior consistent.

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

Got it. `pdtm.pd_run` in the source already had nullable params optional, but to match your “default to null” requirement I’ve now updated `pdtm` so `timeout_seconds` defaults to `None` (null) instead of `300` in **both** the main and `Standalone_Build` copies.

Next I’ll apply the same “nullable → default None” normalization across the other MCP servers that still have `timeout_seconds: int | None = <number>` so those params show up as optional with default null in the tool schema.

---

**User**

When I run "describe pd.pd_run" it is still showing the 'nullable' inputs as being required...

Inputs:
  - args: array | null (required, nullable)
  - save: object | null (required, nullable)
  - stdin_lines: array | null (required, nullable)
  - timeout_seconds: integer | null (required, nullable)
  - tool: string (required)

---

**Cursor**

Plan: I’ll confirm whether this “required but nullable” is coming from FastMCP’s generated JSON schema (not our `describe_tool` helper), then either (a) adjust FastMCP tool registration to use an explicit Pydantic input model with defaults, or (b) ensure you’re running the updated server code (not an older built artifact/container).

Plan: I’ll fix this in two tracks. First I’ll update *all* tool functions across servers where a nullable param still defaults to a number (e.g. `timeout_seconds: int | None = 300`) so the tool schema shows a **null default**. Then we’ll address why `pdtm.pd_run` still appears required—most likely you’re still connected to an older running server/container, so I’ll give you a quick “rebuild + restart” checklist to force the new schema to load.

```python
*** Begin Patch
*** Update File: portscan-mcp-server/src/portscan_mcp_server/server.py
@@
 def naabu_scan(
     targets: list[str],
     *,
@@
     json_output: bool = True,
     extra_args: list[str] | None = None,
-    timeout_seconds: int | None = 300,
+    timeout_seconds: int | None = None,
     save: dict[str, Any] | None = None,
 ) -> dict[str, Any]:
@@
 def naabu_scan_raw(
     targets: list[str],
     *,
     args: list[str],
     i_acknowledge_risk: bool = False,
-    timeout_seconds: int | None = 300,
+    timeout_seconds: int | None = None,
     save: dict[str, Any] | None = None,
 ) -> dict[str, Any]:
@@
 def nmap_scan(
     targets: list[str],
     *,
     args: list[str] | None = None,
     force_unprivileged: bool = True,
-    timeout_seconds: int | None = 900,
+    timeout_seconds: int | None = None,
     save: dict[str, Any] | None = None,
 ) -> dict[str, Any]:
@@
 def nmap_scan_raw(
     targets: list[str],
     *,
     args: list[str],
     i_acknowledge_risk: bool = False,
-    timeout_seconds: int | None = 900,
+    timeout_seconds: int | None = None,
     save: dict[str, Any] | None = None,
 ) -> dict[str, Any]:
@@
 def rustscan_scan(
     targets: list[str],
     *,
@@
     nmap_args: list[str] | None = None,
     extra_args: list[str] | None = None,
-    timeout_seconds: int | None = 900,
+    timeout_seconds: int | None = None,
     save: dict[str, Any] | None = None,
 ) -> dict[str, Any]:
@@
 def rustscan_scan_raw(
     targets: list[str],
     *,
     args: list[str],
@@
     i_acknowledge_risk: bool = False,
-    timeout_seconds: int | None = 900,
+    timeout_seconds: int | None = None,
 ) -> dict[str, Any]:
*** End Patch
```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="portscan-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    *,
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # RustScan may optionally invoke nmap, but this MCP server doesn't do nmap-arg coercion here.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    *,
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """Run naabu, rustscan, and nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        results["naabu"] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        results["rustscan"] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
    except Exception as e:
        results["rustscan"] = {"error": str(e)}

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        results["nmap"] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    return _tool_ok(
        results,
        meta={
            "invalid_targets": bad[:50],
            "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
            "nmap_coercion": (nmap_notes + nmap_notes2),
        },
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4560"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import validate_args, validate_url
from .wpscan_cli import WPScanNotInstalledError, run_wpscan


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="wpscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "arbitrary args can enable aggressive checks / enumeration"},
        )
    return True, None


@mcp.tool()
@register_tool
def wpscan_version() -> dict[str, Any]:
    """Return WPScan version."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok({"stdout": rr.stdout.strip(), "stderr": rr.stderr.strip(), "returncode": rr.returncode})
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_debug_binary() -> dict[str, Any]:
    """Debug helper: return version output and exact command used."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok(
            {"version_stdout": rr.stdout.strip(), "version_stderr": rr.stderr.strip()},
            meta={"command": rr.command, "returncode": rr.returncode},
        )
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_scan(
    url: str,
    *,
    enumerate: str | None = None,
    stealthy: bool = False,
    plugins_detection: str | None = None,
    api_token: str | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
    max_threads: int | None = None,
    headers: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run WPScan against a target URL.

    Upstream docs: https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation

    Notes:
    - API token can be provided via env `WPSCAN_API_TOKEN` or via `api_token`.
    """

    res_url = validate_url(url)
    if not res_url.ok:
        security_event(logger, "invalid_url", url=url)
        return _tool_error(res_url.message or "invalid url")

    args: list[str] = ["--url", url]

    if stealthy:
        args.append("--stealthy")

    if enumerate:
        # wpscan expects formats like: u, u1-100, vp, vt, ap, at
        args.extend(["--enumerate", enumerate])

    if plugins_detection:
        pd = plugins_detection.strip().lower()
        if pd not in {"passive", "mixed", "aggressive"}:
            return _tool_error("plugins_detection must be one of: passive, mixed, aggressive")
        args.extend(["--plugins-detection", pd])

    # API token precedence: explicit param overrides env var.
    token = api_token if api_token is not None else os.getenv("WPSCAN_API_TOKEN")
    if token:
        args.extend(["--api-token", token])

    if proxy:
        args.extend(["--proxy", proxy])

    if user_agent:
        args.extend(["--user-agent", user_agent])

    if max_threads is not None:
        if max_threads < 1 or max_threads > 200:
            return _tool_error("max_threads must be between 1 and 200")
        args.extend(["--max-threads", str(max_threads)])

    if headers:
        # WPScan supports --headers "Header: v; Header2: v"; accept list and join with '; '
        joined = "; ".join([h.strip() for h in headers if (h or "").strip()])
        if joined:
            args.extend(["--headers", joined])

    if extra_args:
        res_args = validate_args(extra_args)
        if not res_args.ok:
            security_event(logger, "invalid_args", error=res_args.message)
            return _tool_error(res_args.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=url, data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def wpscan_scan_raw(
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run WPScan with arbitrary CLI args (no shell)."""

    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    res_args = validate_args(args)
    if not res_args.ok:
        return _tool_error(res_args.message or "invalid args")

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            # Raw mode has no structured target; store the arg vector as target for traceability.
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=" ".join(args), data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4561"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .harvester_cli import HarvesterNotInstalledError, ensure_api_keys_symlinks, run_theharvester
from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import clamp_int, validate_args, validate_domain, validate_sources


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="theharvester")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


@mcp.tool()
@register_tool
def theharvester_version() -> dict[str, Any]:
    """Return theHarvester version (best-effort via `theHarvester -h`/`--version` style output)."""
    try:
        rr = run_theharvester(domain="example.com", sources="all", limit=1, start=0, extra_args=["-h"], timeout_seconds=30)
        return _tool_ok(
            {"stdout": rr.stdout, "stderr": rr.stderr, "returncode": rr.returncode},
            meta={"command": rr.command},
        )
    except HarvesterNotInstalledError as e:
        security_event(logger, "theharvester_not_installed", error=str(e))
        return _tool_error(str(e))
    except Exception as e:
        return _tool_error("failed to run theHarvester", details={"error": str(e)})


@mcp.tool()
@register_tool
def theharvester_sync_keys() -> dict[str, Any]:
    """
    Ensure mounted api keys are linked into theHarvester's expected locations.
    See upstream: https://github.com/laramies/theHarvester/wiki/Installation
    """
    try:
        res = ensure_api_keys_symlinks()
        return _tool_ok(res)
    except Exception as e:
        return _tool_error("failed to sync api keys", details={"error": str(e)})


@mcp.tool()
@register_tool
def theharvester_run(
    *,
    domain: str,
    sources: str = "all",
    limit: int = 100,
    start: int = 0,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run theHarvester and:
    - save output files into the mounted host dir's `output/` folder (HARVESTER_OUTPUT_DIR, default /data/output)
    - return parsed JSON (if theHarvester produced JSON/JSONL/CSV) plus stdout/stderr

    API key file: mount `/data/keys/api-keys.yaml` as described in upstream wiki:
    https://github.com/laramies/theHarvester/wiki/Installation
    """
    d_res = validate_domain(domain)
    if not d_res.ok:
        security_event(logger, "invalid_domain", domain=domain, error=d_res.message)
        return _tool_error(d_res.message or "invalid domain")

    s_res = validate_sources(sources)
    if not s_res.ok:
        security_event(logger, "invalid_sources", sources=sources, error=s_res.message)
        return _tool_error(s_res.message or "invalid sources")

    try:
        limit = clamp_int(limit, min_value=1, max_value=10_000, name="limit")
        start = clamp_int(start, min_value=0, max_value=10_000_000, name="start")
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(timeout_seconds, min_value=30, max_value=7200, name="timeout_seconds")
    except ValueError as e:
        security_event(logger, "invalid_numeric_option", error=str(e))
        return _tool_error(str(e))

    if extra_args:
        a_res = validate_args(extra_args)
        if not a_res.ok:
            security_event(logger, "invalid_args", error=a_res.message)
            return _tool_error(a_res.message or "invalid extra_args")

    try:
        rr = run_theharvester(
            domain=domain,
            sources=sources,
            limit=limit,
            start=start,
            extra_args=extra_args,
            timeout_seconds=timeout_seconds,
        )
    except HarvesterNotInstalledError as e:
        security_event(logger, "theharvester_not_installed", error=str(e))
        return _tool_error(str(e))
    except Exception as e:
        security_event(logger, "theharvester_run_failed", error=str(e))
        return _tool_error("theHarvester failed", details={"error": str(e)})

    meta = {
        "returncode": rr.returncode,
        "command": rr.command,
        "output_dir": os.getenv("HARVESTER_OUTPUT_DIR", "/data/output"),
    }
    payload = {
        "parsed": rr.parsed,
        "stdout": rr.stdout,
        "stderr": rr.stderr,
        "output_files": rr.output_files,
    }
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="theharvester",
                tool_commandline=rr.command,
                scan_target=domain,
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4562"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="portscan-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    *,
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # RustScan may optionally invoke nmap, but this MCP server doesn't do nmap-arg coercion here.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    *,
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """Run naabu, rustscan, and nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        results["naabu"] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        results["rustscan"] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
    except Exception as e:
        results["rustscan"] = {"error": str(e)}

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        results["nmap"] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    return _tool_ok(
        results,
        meta={
            "invalid_targets": bad[:50],
            "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
            "nmap_coercion": (nmap_notes + nmap_notes2),
        },
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4560")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m portscan_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4560

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import validate_args, validate_url
from .wpscan_cli import WPScanNotInstalledError, run_wpscan


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="wpscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "arbitrary args can enable aggressive checks / enumeration"},
        )
    return True, None


@mcp.tool()
@register_tool
def wpscan_version() -> dict[str, Any]:
    """Return WPScan version."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok({"stdout": rr.stdout.strip(), "stderr": rr.stderr.strip(), "returncode": rr.returncode})
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_debug_binary() -> dict[str, Any]:
    """Debug helper: return version output and exact command used."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok(
            {"version_stdout": rr.stdout.strip(), "version_stderr": rr.stderr.strip()},
            meta={"command": rr.command, "returncode": rr.returncode},
        )
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_scan(
    url: str,
    *,
    enumerate: str | None = None,
    stealthy: bool = False,
    plugins_detection: str | None = None,
    api_token: str | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
    max_threads: int | None = None,
    headers: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run WPScan against a target URL.

    Upstream docs: https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation

    Notes:
    - API token can be provided via env `WPSCAN_API_TOKEN` or via `api_token`.
    """

    res_url = validate_url(url)
    if not res_url.ok:
        security_event(logger, "invalid_url", url=url)
        return _tool_error(res_url.message or "invalid url")

    args: list[str] = ["--url", url]

    if stealthy:
        args.append("--stealthy")

    if enumerate:
        # wpscan expects formats like: u, u1-100, vp, vt, ap, at
        args.extend(["--enumerate", enumerate])

    if plugins_detection:
        pd = plugins_detection.strip().lower()
        if pd not in {"passive", "mixed", "aggressive"}:
            return _tool_error("plugins_detection must be one of: passive, mixed, aggressive")
        args.extend(["--plugins-detection", pd])

    # API token precedence: explicit param overrides env var.
    token = api_token if api_token is not None else os.getenv("WPSCAN_API_TOKEN")
    if token:
        args.extend(["--api-token", token])

    if proxy:
        args.extend(["--proxy", proxy])

    if user_agent:
        args.extend(["--user-agent", user_agent])

    if max_threads is not None:
        if max_threads < 1 or max_threads > 200:
            return _tool_error("max_threads must be between 1 and 200")
        args.extend(["--max-threads", str(max_threads)])

    if headers:
        # WPScan supports --headers "Header: v; Header2: v"; accept list and join with '; '
        joined = "; ".join([h.strip() for h in headers if (h or "").strip()])
        if joined:
            args.extend(["--headers", joined])

    if extra_args:
        res_args = validate_args(extra_args)
        if not res_args.ok:
            security_event(logger, "invalid_args", error=res_args.message)
            return _tool_error(res_args.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=url, data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def wpscan_scan_raw(
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run WPScan with arbitrary CLI args (no shell)."""

    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    res_args = validate_args(args)
    if not res_args.ok:
        return _tool_error(res_args.message or "invalid args")

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            # Raw mode has no structured target; store the arg vector as target for traceability.
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=" ".join(args), data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4561")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m wpscan_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4561

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .harvester_cli import HarvesterNotInstalledError, ensure_api_keys_symlinks, run_theharvester
from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import clamp_int, validate_args, validate_domain, validate_sources


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="theharvester")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


@mcp.tool()
@register_tool
def theharvester_version() -> dict[str, Any]:
    """Return theHarvester version (best-effort via `theHarvester -h`/`--version` style output)."""
    try:
        rr = run_theharvester(domain="example.com", sources="all", limit=1, start=0, extra_args=["-h"], timeout_seconds=30)
        return _tool_ok(
            {"stdout": rr.stdout, "stderr": rr.stderr, "returncode": rr.returncode},
            meta={"command": rr.command},
        )
    except HarvesterNotInstalledError as e:
        security_event(logger, "theharvester_not_installed", error=str(e))
        return _tool_error(str(e))
    except Exception as e:
        return _tool_error("failed to run theHarvester", details={"error": str(e)})


@mcp.tool()
@register_tool
def theharvester_sync_keys() -> dict[str, Any]:
    """
    Ensure mounted api keys are linked into theHarvester's expected locations.
    See upstream: https://github.com/laramies/theHarvester/wiki/Installation
    """
    try:
        res = ensure_api_keys_symlinks()
        return _tool_ok(res)
    except Exception as e:
        return _tool_error("failed to sync api keys", details={"error": str(e)})


@mcp.tool()
@register_tool
def theharvester_run(
    *,
    domain: str,
    sources: str = "all",
    limit: int = 100,
    start: int = 0,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run theHarvester and:
    - save output files into the mounted host dir's `output/` folder (HARVESTER_OUTPUT_DIR, default /data/output)
    - return parsed JSON (if theHarvester produced JSON/JSONL/CSV) plus stdout/stderr

    API key file: mount `/data/keys/api-keys.yaml` as described in upstream wiki:
    https://github.com/laramies/theHarvester/wiki/Installation
    """
    d_res = validate_domain(domain)
    if not d_res.ok:
        security_event(logger, "invalid_domain", domain=domain, error=d_res.message)
        return _tool_error(d_res.message or "invalid domain")

    s_res = validate_sources(sources)
    if not s_res.ok:
        security_event(logger, "invalid_sources", sources=sources, error=s_res.message)
        return _tool_error(s_res.message or "invalid sources")

    try:
        limit = clamp_int(limit, min_value=1, max_value=10_000, name="limit")
        start = clamp_int(start, min_value=0, max_value=10_000_000, name="start")
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(timeout_seconds, min_value=30, max_value=7200, name="timeout_seconds")
    except ValueError as e:
        security_event(logger, "invalid_numeric_option", error=str(e))
        return _tool_error(str(e))

    if extra_args:
        a_res = validate_args(extra_args)
        if not a_res.ok:
            security_event(logger, "invalid_args", error=a_res.message)
            return _tool_error(a_res.message or "invalid extra_args")

    try:
        rr = run_theharvester(
            domain=domain,
            sources=sources,
            limit=limit,
            start=start,
            extra_args=extra_args,
            timeout_seconds=timeout_seconds,
        )
    except HarvesterNotInstalledError as e:
        security_event(logger, "theharvester_not_installed", error=str(e))
        return _tool_error(str(e))
    except Exception as e:
        security_event(logger, "theharvester_run_failed", error=str(e))
        return _tool_error("theHarvester failed", details={"error": str(e)})

    meta = {
        "returncode": rr.returncode,
        "command": rr.command,
        "output_dir": os.getenv("HARVESTER_OUTPUT_DIR", "/data/output"),
    }
    payload = {
        "parsed": rr.parsed,
        "stdout": rr.stdout,
        "stderr": rr.stderr,
        "output_files": rr.output_files,
    }
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="theharvester",
                tool_commandline=rr.command,
                scan_target=domain,
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4562")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m theharvester_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4562

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

### Why `describe pd.pd_run` still shows “required, nullable”
In JSON-schema land, **“required + nullable”** means: *the field may be null, but you must still send it*. That typically happens when the **running server** is still using an older schema where those params had **no defaults**.

In the code you now have, `pd_run` params are **optional with defaults** (so they should not be required):

```225:232:Standalone_Build/pdtm-mcp-server/src/pdtm_mcp_server/server.py
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
```

### What you need to do (most likely)
**Rebuild + restart the MCP server you’re actually connected to** (Cursor caches the tool schema from the running process).

- **If you’re running via Podman image** (e.g. `cursor-stdio.sh`): rebuild that image, then stop/start the server.
- **If you’re running Standalone_Build**: rerun your build/rebuild script, then restart the stdio runner.

After restart, `describe …` should show only `tool` as required.

### Code changes I’ve made as part of your “nullable ⇒ optional/default null” request
- **`pdtm`**: `timeout_seconds` now defaults to **`None`** (null) for `pd_run`, `pd_run_raw`, and `pd_smart` (both main + Standalone_Build).
- **Also normalized other servers** where nullable `timeout_seconds` had numeric defaults → now **`None`**:
  - `portscan-mcp-server` (and Standalone_Build copy)
  - `wpscan-mcp-server` (and Standalone_Build copy)
  - `theharvester-mcp-server` (and Standalone_Build copy)

If you tell me **how you’re launching the `pd` server** (Podman `cursor-stdio.sh`, Standalone `run-mcp-stdio.sh`, etc.), I’ll give you the exact 2–3 commands to rebuild/restart so the schema updates immediately.

```python
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
```

---

**User**

I am running the "pdtm" server via the following line in the mcp.json:

"pdtm": {
      "command": "./run-mcp-stdio.sh",
      "args": ["pdtm_mcp_server.server"],
      "env": { "MCP_TRANSPORT": "stdio" }
    }

---

**Cursor**

Plan: I’ll inspect `Standalone_Build/run-mcp-stdio.sh` to see exactly how it launches `pdtm_mcp_server.server` (what Python env + what `PYTHONPATH`), then we’ll adjust it (or the `mcp.json` command) so Cursor definitely runs the **updated source** and refreshes the tool schema (making nullable params truly optional).

Nice—we found the real culprit: **FastMCP 2.14.1 marks optional params as required whenever your functions use `from __future__ import annotations`** (because annotations become strings). Next I’ll patch each server’s `register_tool()` decorator to “de-stringify” annotations via `typing.get_type_hints()` *before* `@mcp.tool()` runs, which fixes the tool schema without removing future-annotations everywhere.

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="portscan-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    *,
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # RustScan may optionally invoke nmap, but this MCP server doesn't do nmap-arg coercion here.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    *,
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """Run naabu, rustscan, and nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        results["naabu"] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        results["rustscan"] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
    except Exception as e:
        results["rustscan"] = {"error": str(e)}

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        results["nmap"] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    return _tool_ok(
        results,
        meta={
            "invalid_targets": bad[:50],
            "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
            "nmap_coercion": (nmap_notes + nmap_notes2),
        },
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4560"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import validate_args, validate_url
from .wpscan_cli import WPScanNotInstalledError, run_wpscan


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="wpscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "arbitrary args can enable aggressive checks / enumeration"},
        )
    return True, None


@mcp.tool()
@register_tool
def wpscan_version() -> dict[str, Any]:
    """Return WPScan version."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok({"stdout": rr.stdout.strip(), "stderr": rr.stderr.strip(), "returncode": rr.returncode})
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_debug_binary() -> dict[str, Any]:
    """Debug helper: return version output and exact command used."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok(
            {"version_stdout": rr.stdout.strip(), "version_stderr": rr.stderr.strip()},
            meta={"command": rr.command, "returncode": rr.returncode},
        )
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_scan(
    url: str,
    *,
    enumerate: str | None = None,
    stealthy: bool = False,
    plugins_detection: str | None = None,
    api_token: str | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
    max_threads: int | None = None,
    headers: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run WPScan against a target URL.

    Upstream docs: https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation

    Notes:
    - API token can be provided via env `WPSCAN_API_TOKEN` or via `api_token`.
    """

    res_url = validate_url(url)
    if not res_url.ok:
        security_event(logger, "invalid_url", url=url)
        return _tool_error(res_url.message or "invalid url")

    args: list[str] = ["--url", url]

    if stealthy:
        args.append("--stealthy")

    if enumerate:
        # wpscan expects formats like: u, u1-100, vp, vt, ap, at
        args.extend(["--enumerate", enumerate])

    if plugins_detection:
        pd = plugins_detection.strip().lower()
        if pd not in {"passive", "mixed", "aggressive"}:
            return _tool_error("plugins_detection must be one of: passive, mixed, aggressive")
        args.extend(["--plugins-detection", pd])

    # API token precedence: explicit param overrides env var.
    token = api_token if api_token is not None else os.getenv("WPSCAN_API_TOKEN")
    if token:
        args.extend(["--api-token", token])

    if proxy:
        args.extend(["--proxy", proxy])

    if user_agent:
        args.extend(["--user-agent", user_agent])

    if max_threads is not None:
        if max_threads < 1 or max_threads > 200:
            return _tool_error("max_threads must be between 1 and 200")
        args.extend(["--max-threads", str(max_threads)])

    if headers:
        # WPScan supports --headers "Header: v; Header2: v"; accept list and join with '; '
        joined = "; ".join([h.strip() for h in headers if (h or "").strip()])
        if joined:
            args.extend(["--headers", joined])

    if extra_args:
        res_args = validate_args(extra_args)
        if not res_args.ok:
            security_event(logger, "invalid_args", error=res_args.message)
            return _tool_error(res_args.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=url, data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def wpscan_scan_raw(
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run WPScan with arbitrary CLI args (no shell)."""

    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    res_args = validate_args(args)
    if not res_args.ok:
        return _tool_error(res_args.message or "invalid args")

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            # Raw mode has no structured target; store the arg vector as target for traceability.
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=" ".join(args), data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4561"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .harvester_cli import HarvesterNotInstalledError, ensure_api_keys_symlinks, run_theharvester
from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import clamp_int, validate_args, validate_domain, validate_sources


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="theharvester")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


@mcp.tool()
@register_tool
def theharvester_version() -> dict[str, Any]:
    """Return theHarvester version (best-effort via `theHarvester -h`/`--version` style output)."""
    try:
        rr = run_theharvester(domain="example.com", sources="all", limit=1, start=0, extra_args=["-h"], timeout_seconds=30)
        return _tool_ok(
            {"stdout": rr.stdout, "stderr": rr.stderr, "returncode": rr.returncode},
            meta={"command": rr.command},
        )
    except HarvesterNotInstalledError as e:
        security_event(logger, "theharvester_not_installed", error=str(e))
        return _tool_error(str(e))
    except Exception as e:
        return _tool_error("failed to run theHarvester", details={"error": str(e)})


@mcp.tool()
@register_tool
def theharvester_sync_keys() -> dict[str, Any]:
    """
    Ensure mounted api keys are linked into theHarvester's expected locations.
    See upstream: https://github.com/laramies/theHarvester/wiki/Installation
    """
    try:
        res = ensure_api_keys_symlinks()
        return _tool_ok(res)
    except Exception as e:
        return _tool_error("failed to sync api keys", details={"error": str(e)})


@mcp.tool()
@register_tool
def theharvester_run(
    *,
    domain: str,
    sources: str = "all",
    limit: int = 100,
    start: int = 0,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run theHarvester and:
    - save output files into the mounted host dir's `output/` folder (HARVESTER_OUTPUT_DIR, default /data/output)
    - return parsed JSON (if theHarvester produced JSON/JSONL/CSV) plus stdout/stderr

    API key file: mount `/data/keys/api-keys.yaml` as described in upstream wiki:
    https://github.com/laramies/theHarvester/wiki/Installation
    """
    d_res = validate_domain(domain)
    if not d_res.ok:
        security_event(logger, "invalid_domain", domain=domain, error=d_res.message)
        return _tool_error(d_res.message or "invalid domain")

    s_res = validate_sources(sources)
    if not s_res.ok:
        security_event(logger, "invalid_sources", sources=sources, error=s_res.message)
        return _tool_error(s_res.message or "invalid sources")

    try:
        limit = clamp_int(limit, min_value=1, max_value=10_000, name="limit")
        start = clamp_int(start, min_value=0, max_value=10_000_000, name="start")
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(timeout_seconds, min_value=30, max_value=7200, name="timeout_seconds")
    except ValueError as e:
        security_event(logger, "invalid_numeric_option", error=str(e))
        return _tool_error(str(e))

    if extra_args:
        a_res = validate_args(extra_args)
        if not a_res.ok:
            security_event(logger, "invalid_args", error=a_res.message)
            return _tool_error(a_res.message or "invalid extra_args")

    try:
        rr = run_theharvester(
            domain=domain,
            sources=sources,
            limit=limit,
            start=start,
            extra_args=extra_args,
            timeout_seconds=timeout_seconds,
        )
    except HarvesterNotInstalledError as e:
        security_event(logger, "theharvester_not_installed", error=str(e))
        return _tool_error(str(e))
    except Exception as e:
        security_event(logger, "theharvester_run_failed", error=str(e))
        return _tool_error("theHarvester failed", details={"error": str(e)})

    meta = {
        "returncode": rr.returncode,
        "command": rr.command,
        "output_dir": os.getenv("HARVESTER_OUTPUT_DIR", "/data/output"),
    }
    payload = {
        "parsed": rr.parsed,
        "stdout": rr.stdout,
        "stderr": rr.stderr,
        "output_files": rr.output_files,
    }
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="theharvester",
                tool_commandline=rr.command,
                scan_target=domain,
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4562"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .paths import exploitdb_dir
from .searchsploit_cli import run_searchsploit, update_exploitdb


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="searchsploit")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


@mcp.tool()
@register_tool
def searchsploit_search(
    terms: list[str],
    *,
    case_insensitive: bool = True,
    max_results_hint: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run Searchsploit against the local ExploitDB clone.
    """
    cleaned = [t.strip() for t in (terms or []) if (t or "").strip()]
    if not cleaned:
        return _tool_error("terms must not be empty")

    flags: list[str] = []
    if case_insensitive:
        flags.append("-i")

    # Searchsploit output is text; we return raw stdout.
    rr = run_searchsploit(cleaned, flags=flags)
    meta = {"returncode": rr.returncode, "command": rr.command, "max_results_hint": max_results_hint}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="searchsploit",
                tool_commandline=rr.command,
                scan_target=" ".join(cleaned),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}
    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def searchsploit_read_exploit(relative_path: str, *, max_bytes: int = 200_000) -> dict[str, Any]:
    """
    Read an exploit file from the local ExploitDB clone (for source inspection).
    """
    rel = (relative_path or "").lstrip("/").strip()
    if not rel:
        return _tool_error("relative_path is required")

    base = exploitdb_dir().resolve()
    target = (base / rel).resolve()
    if not str(target).startswith(str(base) + os.sep):
        security_event(logger, "path_traversal_blocked", relative_path=relative_path)
        return _tool_error("path is outside exploitdb directory")
    if not target.exists() or not target.is_file():
        return _tool_error("file not found", details={"path": str(target)})

    data = target.read_bytes()
    if len(data) > max_bytes:
        data = data[:max_bytes]
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = repr(data[:2000])
    return _tool_ok({"path": str(target), "content": text, "truncated": target.stat().st_size > max_bytes})


@mcp.tool()
@register_tool
def searchsploit_scan_source(
    pattern: str,
    *,
    max_matches: int = 200,
) -> dict[str, Any]:
    """
    Simple source scanning over the exploitdb tree (grep-like).
    Returns file paths containing the pattern (case-insensitive).
    """
    pat = (pattern or "").strip()
    if not pat:
        return _tool_error("pattern is required")
    if len(pat) > 200:
        return _tool_error("pattern too long")

    base = exploitdb_dir()
    matches: list[str] = []
    # naive scan to avoid requiring rg in image; keep bounded
    for p in base.rglob("*"):
        if not p.is_file():
            continue
        try:
            b = p.read_bytes()
        except Exception:
            continue
        if pat.lower().encode() in b.lower():
            matches.append(str(p))
            if len(matches) >= max_matches:
                break

    return _tool_ok({"pattern": pat, "matches": matches, "max_matches": max_matches})


@mcp.tool()
@register_tool
def searchsploit_update() -> dict[str, Any]:
    """
    Update ExploitDB repos inside the running container (git pull).
    """
    return _tool_ok(update_exploitdb())


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4564"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

import httpx
from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .policy import default_engines, requires_opt_in, split_requested_engines
from .validation import validate_engines, validate_query


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="searx")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _searx_url() -> str:
    # IMPORTANT: should remain internal-only (127.0.0.1) inside the container.
    return os.getenv("SEARXNG_URL", "http://127.0.0.1:8080").rstrip("/")

def _timeout_limit_seconds(default: float = 8.0) -> float:
    """
    Default SearXNG backend engine timeout limit (seconds).
    If engines are blocked/unreachable, this prevents long hangs.
    """
    raw = os.getenv("SEARX_TIMEOUT_LIMIT_SECONDS", "").strip()
    if not raw:
        return default
    try:
        v = float(raw)
    except ValueError:
        return default
    if v <= 0:
        return default
    return min(v, 60.0)

def _user_agent() -> str:
    # SearXNG botdetection may block non-browser user agents with 403.
    # Use a reasonable default but allow overrides.
    return os.getenv(
        "SEARX_MCP_USER_AGENT",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    )

def _accept_language(requested_language: str | None) -> str:
    # Keep it simple; SearXNG expects a normal Accept-Language header.
    lang = (requested_language or "").strip()
    if not lang:
        return "en-US,en;q=0.9"
    return f"{lang},en;q=0.8"

def _client_ip() -> str:
    # SearXNG botdetection expects a client IP header in some configurations.
    # Since MCP and SearXNG are co-located in the same container, default to loopback.
    return os.getenv("SEARX_MCP_CLIENT_IP", "127.0.0.1").strip() or "127.0.0.1"


@mcp.tool()
@register_tool
def searx_policy() -> dict[str, Any]:
    """Return the engine privacy policy enforced by this MCP server."""
    return _tool_ok(
        {
            "default_engines": default_engines(),
            "non_private_engines_require_opt_in": sorted(list({"google", "bing", "yahoo", "yandex", "baidu"})),
        }
    )


@mcp.tool()
@register_tool
async def searx_search(
    query: str,
    *,
    engines: list[str] | None = None,
    categories: str | None = None,
    language: str | None = None,
    time_range: str | None = None,
    safesearch: int | None = 1,
    page: int | None = 1,
    max_results: int | None = 25,
    allow_non_private_engines: bool = False,
    timeout_seconds: float | None = 20.0,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Query SearXNG via its internal HTTP API and return JSON.

    Privacy defaults:
    - Uses DuckDuckGo by default
    - Engines like Google/Bing are only allowed when explicitly requested via `engines`
      AND `allow_non_private_engines=true`.
    """

    qv = validate_query(query)
    if not qv.ok:
        security_event(logger, "invalid_query", error=qv.message)
        return _tool_error(qv.message or "invalid query")

    req_engines = split_requested_engines(engines)
    if not req_engines:
        req_engines = default_engines()

    ev = validate_engines(req_engines)
    if not ev.ok:
        security_event(logger, "invalid_engines", error=ev.message)
        return _tool_error(ev.message or "invalid engines")

    needs_opt_in = requires_opt_in(req_engines)
    if needs_opt_in and not allow_non_private_engines:
        security_event(logger, "blocked_non_private_engines", engines=needs_opt_in)
        return _tool_error(
            "non-private engines requested; explicit opt-in required",
            details={"blocked_engines": needs_opt_in, "hint": "set allow_non_private_engines=true"},
        )

    if max_results is not None and (max_results < 1 or max_results > 100):
        return _tool_error("max_results must be between 1 and 100")

    params: dict[str, Any] = {
        "q": query.strip(),
        "format": "json",
        "engines": ",".join(req_engines),
        "pageno": page or 1,
    }
    if categories:
        params["categories"] = categories
    if language:
        params["language"] = language
    if time_range:
        params["time_range"] = time_range
    if safesearch is not None:
        params["safesearch"] = safesearch

    # SearXNG supports limiting backend engine time via `timeout_limit` (seconds).
    # This helps prevent long hangs when engines are blocked/unreachable.
    params["timeout_limit"] = _timeout_limit_seconds()

    url = f"{_searx_url()}/search"

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            headers = {
                "Accept": "application/json",
                "User-Agent": _user_agent(),
                "Accept-Language": _accept_language(language),
                "X-Forwarded-For": _client_ip(),
                "X-Real-IP": _client_ip(),
            }
            resp = await client.get(
                url,
                params=params,
                headers=headers,
            )
            # Some SearXNG instances are configured with `server.method: POST` and may forbid GET searches.
            if resp.status_code == 403:
                resp = await client.post(
                    url,
                    data=params,
                    headers=headers,
                )
    except httpx.TimeoutException as e:
        security_event(
            logger,
            "searx_request_timeout",
            error=str(e),
            internal_url=url,
            timeout_seconds=timeout_seconds,
        )
        return _tool_error(
            "searx request timed out",
            details={
                "internal_url": url,
                "timeout_seconds": timeout_seconds,
                "hint": "check that SearXNG is running and reachable at SEARXNG_URL inside the container (default http://127.0.0.1:8080)",
            },
        )
    except httpx.RequestError as e:
        # Covers DNS errors, connection refused, TLS errors, etc.
        security_event(
            logger,
            "searx_request_error",
            error=str(e),
            error_type=type(e).__name__,
            internal_url=url,
        )
        return _tool_error(
            "failed to reach searx",
            details={
                "internal_url": url,
                "error_type": type(e).__name__,
                "error": str(e),
                "hint": "SearXNG may not be running. Verify the container starts gunicorn successfully and SEARXNG_URL points at the internal bind address.",
            },
        )

    if resp.status_code != 200:
        security_event(logger, "searx_http_error", status=resp.status_code)
        return _tool_error("searx returned non-200", details={"status": resp.status_code, "body": resp.text[:1000]})

    try:
        data = resp.json()
    except Exception as e:
        security_event(
            logger,
            "searx_invalid_json",
            error=str(e),
            status=resp.status_code,
            content_type=resp.headers.get("content-type"),
        )
        return _tool_error(
            "searx returned invalid JSON",
            details={
                "status": resp.status_code,
                "content_type": resp.headers.get("content-type"),
                "body": resp.text[:1000],
            },
        )

    if isinstance(data, dict) and max_results is not None:
        results = data.get("results")
        if isinstance(results, list):
            data["results"] = results[:max_results]

    # Compute which upstream engine(s) actually produced the returned results.
    # SearXNG often annotates each result with `engine` and/or `engines`.
    result_engine_counts: dict[str, int] = {}
    engines_in_results: set[str] = set()
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, list):
            for r in results:
                if not isinstance(r, dict):
                    continue
                eng = r.get("engine")
                if isinstance(eng, str) and eng.strip():
                    k = eng.strip()
                    result_engine_counts[k] = result_engine_counts.get(k, 0) + 1
                    engines_in_results.add(k)
                engs = r.get("engines")
                if isinstance(engs, list):
                    for e in engs:
                        if isinstance(e, str) and e.strip():
                            engines_in_results.add(e.strip())

    meta = {
            # Engines requested/allowed by this MCP server (what we asked SearXNG to use).
            "engines_used": req_engines,
            # Engines that actually show up in the returned result set (derived from SearXNG response).
            "result_engines": sorted(engines_in_results),
            "result_engine_counts": dict(sorted(result_engine_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            "internal_url": url,
            "timeout_limit_seconds": params.get("timeout_limit"),
            "note": "SearXNG is bound to 127.0.0.1 inside the container and is not exposed externally.",
    }

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="searx",
                tool_commandline={"q": params.get("q"), "engines": params.get("engines"), "pageno": params.get("pageno")},
                scan_target=str(params.get("q") or ""),
                data={"result": data, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(data, meta=meta)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4563"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP
from shodan import Shodan
from shodan.exception import APIError

from .env_loader import load_dotenv_if_present
from .filters import describe_filter, list_known_filters
from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import (
    ValidationResult,
    clamp_int,
    validate_filter_expression,
    validate_query,
)

load_dotenv_if_present()

configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="shodan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _validate_list(items: list[str] | None, validator) -> tuple[list[str], list[tuple[str, str]]]:
    if not items:
        return [], []
    ok: list[str] = []
    bad: list[tuple[str, str]] = []
    for x in items:
        x2 = (x or "").strip()
        if not x2:
            continue
        res: ValidationResult = validator(x2)
        if res.ok:
            ok.append(x2)
        else:
            bad.append((x2, res.message or "invalid"))
    return ok, bad


def _env_api_key() -> tuple[str | None, dict[str, Any] | None]:
    """
    Returns (api_key, error_payload). Loads from environment (`SHODAN_API_KEY`).
    The `.env` file is loaded at import-time if present.
    """
    k = os.getenv("SHODAN_API_KEY", "").strip()
    if not k:
        security_event(logger, "missing_api_key_env")
        return None, _tool_error(
            "missing SHODAN_API_KEY",
            details={
                "hint": "Create shodan-mcp-server/.env with SHODAN_API_KEY=... and restart the container",
                "env_var": "SHODAN_API_KEY",
            },
        )
    # Avoid logging the key; only validate basic shape.
    if "\n" in k or "\r" in k or "\x00" in k or len(k) < 16:
        security_event(logger, "invalid_api_key_env_format")
        return None, _tool_error("SHODAN_API_KEY format looks invalid")
    return k, None


def _build_query(
    query: str,
    *,
    filters: list[str] | None,
    country: str | None,
    org: str | None,
    asn: str | None,
    net: str | None,
    port: int | None,
    product: str | None,
    hostname: str | None,
    city: str | None,
) -> tuple[str, list[tuple[str, str]]]:
    parts: list[str] = [query.strip()]
    bad: list[tuple[str, str]] = []

    def maybe_quote(v: str) -> str:
        """
        Preserve quotes if the user already provided them; otherwise wrap in double-quotes.
        Avoid nested f-strings/backslash escapes so this stays valid on Python 3.12+.
        """
        v2 = (v or "").strip()
        if v2.startswith(("\"", "'")):
            return v2
        return f"\"{v2}\""

    def add_expr(expr: str) -> None:
        res = validate_filter_expression(expr)
        if res.ok:
            parts.append(expr)
        else:
            bad.append((expr, res.message or "invalid"))

    if country:
        add_expr(f"country:{country.strip()}")
    if org:
        add_expr(f"org:{maybe_quote(org)}")
    if asn:
        add_expr(f"asn:{asn.strip()}")
    if net:
        add_expr(f"net:{net.strip()}")
    if port is not None:
        add_expr(f"port:{port}")
    if product:
        add_expr(f"product:{maybe_quote(product)}")
    if hostname:
        add_expr(f"hostname:{hostname.strip()}")
    if city:
        add_expr(f"city:{maybe_quote(city)}")

    ok_filters, bad_filters = _validate_list(filters, validate_filter_expression)
    bad.extend(bad_filters)
    parts.extend(ok_filters)

    return " ".join([p for p in parts if p]).strip(), bad


def _summarize_matches(matches: list[dict[str, Any]], *, max_results: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in matches[:max_results]:
        data = (m.get("data") or "").strip()
        if len(data) > 500:
            data = data[:500] + "…"
        loc = m.get("location") or {}
        out.append(
            {
                "ip_str": m.get("ip_str"),
                "port": m.get("port"),
                "transport": m.get("transport"),
                "org": m.get("org"),
                "isp": m.get("isp"),
                "asn": m.get("asn"),
                "hostnames": m.get("hostnames"),
                "domains": m.get("domains"),
                "product": m.get("product"),
                "version": m.get("version"),
                "timestamp": m.get("timestamp"),
                "location": {
                    "country_code": loc.get("country_code"),
                    "country_name": loc.get("country_name"),
                    "region_code": loc.get("region_code"),
                    "city": loc.get("city"),
                    "latitude": loc.get("latitude"),
                    "longitude": loc.get("longitude"),
                },
                "data_excerpt": data,
            }
        )
    return out


@mcp.tool()
@register_tool
def shodan_search(
    query: str,
    filters: list[str] | None = None,
    country: str | None = None,
    org: str | None = None,
    asn: str | None = None,
    net: str | None = None,
    port: int | None = None,
    product: str | None = None,
    hostname: str | None = None,
    city: str | None = None,
    page: int | None = 1,
    max_results: int | None = 25,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Search Shodan using a base `query` and optional filters.

    - If Shodan reports more than 25 results, only the first 25 are returned (configurable via `max_results`).
    - This server reads the Shodan API key from `SHODAN_API_KEY` (loaded from `.env` if present).

    Filters can be provided in two ways:
    - convenience params (country/org/asn/net/port/product/hostname/city)
    - raw filter expressions: `filters=["country:US", "port:443", ...]`
    """
    qv = validate_query(query)
    if not qv.ok:
        security_event(logger, "invalid_query", error=qv.message)
        return _tool_error(qv.message or "invalid query")

    try:
        page2 = clamp_int(int(page or 1), min_value=1, max_value=100, name="page")
    except ValueError as e:
        security_event(logger, "invalid_page", error=str(e))
        return _tool_error(str(e))

    try:
        mr = clamp_int(int(max_results or 25), min_value=1, max_value=25, name="max_results")
    except ValueError as e:
        security_event(logger, "invalid_max_results", error=str(e))
        return _tool_error(str(e))

    if port is not None:
        try:
            port = clamp_int(int(port), min_value=1, max_value=65535, name="port")
        except ValueError as e:
            security_event(logger, "invalid_port", error=str(e))
            return _tool_error(str(e))

    api_key2, err = _env_api_key()
    if err:
        return err

    full_query, bad_filters = _build_query(
        query,
        filters=filters,
        country=country,
        org=org,
        asn=asn,
        net=net,
        port=port,
        product=product,
        hostname=hostname,
        city=city,
    )
    if bad_filters:
        security_event(logger, "invalid_filters", count=len(bad_filters), examples=bad_filters[:5])
        return _tool_error("invalid filter(s) provided", details={"invalid": bad_filters[:50]})

    api = Shodan(api_key2)  # type: ignore[arg-type]

    try:
        res = api.search(full_query, page=page2)
    except APIError as e:
        security_event(logger, "shodan_api_error", error=str(e))
        return _tool_error("Shodan API error", details={"message": str(e)})
    except Exception as e:
        security_event(logger, "shodan_search_error", error=str(e))
        return _tool_error("Shodan search failed", details={"message": str(e)})

    total = int(res.get("total") or 0)
    matches = res.get("matches") or []
    if not isinstance(matches, list):
        matches = []

    summarized = _summarize_matches(matches, max_results=mr)

    meta = {
        "query": full_query,
        "page": page2,
        "total": total,
        "returned_by_shodan_on_this_page": len(matches),
        "shown": len(summarized),
        "note": "If total is larger than shown, paginate with `page=` to view more results.",
    }
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="shodan",
                tool_commandline={"query": full_query, "page": page2, "max_results": mr},
                scan_target=full_query,
                data={"result": summarized, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        summarized,
        meta=meta,
    )


@mcp.tool()
@register_tool
def shodan_filters(name: str | None = None) -> dict[str, Any]:
    """
    List known Shodan filters, or describe one filter by name.

    - `shodan_filters()` returns a list of filters (name/syntax/description).
    - `shodan_filters(name="country")` returns detailed info for a single filter.
    """
    if not name:
        return _tool_ok(list_known_filters(), meta={"count": len(list_known_filters())})

    info = describe_filter(name)
    if not info:
        return _tool_error(
            "unknown filter",
            details={
                "name": (name or "").strip(),
                "hint": "Use shodan_filters() to list known filters; you can still use arbitrary filters via shodan_search(filters=[...]).",
            },
        )
    return _tool_ok(info)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4565")
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport in {"stdio"}:
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4565

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info(
            "Starting MCP server",
            extra={"transport": transport, "host": host, "port": port, "path": path or ""},
        )
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info(
        "Starting MCP server with fallback transport",
        extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""},
    )
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from fastmcp import FastMCP
from pymongo import MongoClient
from pymongo.collection import Collection

try:
    from bson import ObjectId
except Exception:  # pragma: no cover
    ObjectId = None  # type: ignore


mcp = FastMCP(name="mongo-mcp")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mongo_collection() -> Collection:
    uri = os.getenv("MONGO_URI", "").strip()
    if not uri:
        raise ValueError("MONGO_URI is not set")
    db_name = (os.getenv("MONGO_DB", "") or "mcp_db").strip() or "mcp_db"
    coll_name = (os.getenv("MONGO_COLLECTION", "") or "results").strip() or "results"
    client = MongoClient(uri, serverSelectionTimeoutMS=3000)
    return client[db_name][coll_name]


def _parse_iso(ts: str) -> datetime:
    # Accept Z suffix or offset-aware ISO.
    s = (ts or "").strip()
    if not s:
        raise ValueError("timestamp is required")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


@mcp.tool()
@register_tool
def mongo_ping() -> dict[str, Any]:
    """Ping MongoDB and return basic connection info."""
    try:
        coll = _mongo_collection()
        coll.database.client.admin.command("ping")
        return _tool_ok({"ok": True, "ts": _utc_now()}, meta={"db": coll.database.name, "collection": coll.name})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def mongo_find(
    *,
    tool_name: str | None = None,
    scan_target: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 50,
    skip: int = 0,
    sort_desc: bool = True,
) -> dict[str, Any]:
    """
    Search `mcp_db.results` for run records by tool_name, scan_target, and/or date_run range.
    Returns documents with `_id` serialized as string.
    """
    try:
        limit = int(limit)
        skip = int(skip)
        if limit < 1 or limit > 1000:
            return _tool_error("limit must be between 1 and 1000")
        if skip < 0 or skip > 1_000_000:
            return _tool_error("skip must be between 0 and 1000000")

        q: dict[str, Any] = {}
        if tool_name:
            q["tool_name"] = (tool_name or "").strip().lower()
        if scan_target:
            q["scan_target"] = (scan_target or "").strip()

        if since or until:
            rng: dict[str, Any] = {}
            if since:
                rng["$gte"] = _parse_iso(since).isoformat()
            if until:
                rng["$lte"] = _parse_iso(until).isoformat()
            q["date_run"] = rng

        coll = _mongo_collection()
        sort_dir = -1 if sort_desc else 1
        cur = coll.find(q).sort("date_run", sort_dir).skip(skip).limit(limit)
        out: list[dict[str, Any]] = []
        for doc in cur:
            doc2 = dict(doc)
            _id = doc2.get("_id")
            doc2["_id"] = str(_id)
            out.append(doc2)
        return _tool_ok(out, meta={"count": len(out), "limit": limit, "skip": skip})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def mongo_get(id: str) -> dict[str, Any]:
    """Get a single result record by MongoDB ObjectId string."""
    try:
        if ObjectId is None:
            return _tool_error("bson ObjectId is unavailable in this environment")
        oid = ObjectId((id or "").strip())
        coll = _mongo_collection()
        doc = coll.find_one({"_id": oid})
        if not doc:
            return _tool_error("not found")
        doc2 = dict(doc)
        doc2["_id"] = str(doc2.get("_id"))
        return _tool_ok(doc2)
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def mongo_stats() -> dict[str, Any]:
    """Return counts grouped by tool_name (top 50) and total count."""
    try:
        coll = _mongo_collection()
        total = coll.count_documents({})
        pipeline = [
            {"$group": {"_id": "$tool_name", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 50},
        ]
        grouped = list(coll.aggregate(pipeline))
        out = [{"tool_name": g.get("_id"), "count": int(g.get("count") or 0)} for g in grouped]
        return _tool_ok({"total": int(total), "by_tool": out})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4570")
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        port = 4570
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="portscan-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    *,
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # RustScan may optionally invoke nmap, but this MCP server doesn't do nmap-arg coercion here.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    *,
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """Run naabu, rustscan, and nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        results["naabu"] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        results["rustscan"] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
    except Exception as e:
        results["rustscan"] = {"error": str(e)}

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        results["nmap"] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    return _tool_ok(
        results,
        meta={
            "invalid_targets": bad[:50],
            "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
            "nmap_coercion": (nmap_notes + nmap_notes2),
        },
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4560")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m portscan_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4560

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import validate_args, validate_url
from .wpscan_cli import WPScanNotInstalledError, run_wpscan


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="wpscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "arbitrary args can enable aggressive checks / enumeration"},
        )
    return True, None


@mcp.tool()
@register_tool
def wpscan_version() -> dict[str, Any]:
    """Return WPScan version."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok({"stdout": rr.stdout.strip(), "stderr": rr.stderr.strip(), "returncode": rr.returncode})
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_debug_binary() -> dict[str, Any]:
    """Debug helper: return version output and exact command used."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok(
            {"version_stdout": rr.stdout.strip(), "version_stderr": rr.stderr.strip()},
            meta={"command": rr.command, "returncode": rr.returncode},
        )
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_scan(
    url: str,
    *,
    enumerate: str | None = None,
    stealthy: bool = False,
    plugins_detection: str | None = None,
    api_token: str | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
    max_threads: int | None = None,
    headers: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run WPScan against a target URL.

    Upstream docs: https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation

    Notes:
    - API token can be provided via env `WPSCAN_API_TOKEN` or via `api_token`.
    """

    res_url = validate_url(url)
    if not res_url.ok:
        security_event(logger, "invalid_url", url=url)
        return _tool_error(res_url.message or "invalid url")

    args: list[str] = ["--url", url]

    if stealthy:
        args.append("--stealthy")

    if enumerate:
        # wpscan expects formats like: u, u1-100, vp, vt, ap, at
        args.extend(["--enumerate", enumerate])

    if plugins_detection:
        pd = plugins_detection.strip().lower()
        if pd not in {"passive", "mixed", "aggressive"}:
            return _tool_error("plugins_detection must be one of: passive, mixed, aggressive")
        args.extend(["--plugins-detection", pd])

    # API token precedence: explicit param overrides env var.
    token = api_token if api_token is not None else os.getenv("WPSCAN_API_TOKEN")
    if token:
        args.extend(["--api-token", token])

    if proxy:
        args.extend(["--proxy", proxy])

    if user_agent:
        args.extend(["--user-agent", user_agent])

    if max_threads is not None:
        if max_threads < 1 or max_threads > 200:
            return _tool_error("max_threads must be between 1 and 200")
        args.extend(["--max-threads", str(max_threads)])

    if headers:
        # WPScan supports --headers "Header: v; Header2: v"; accept list and join with '; '
        joined = "; ".join([h.strip() for h in headers if (h or "").strip()])
        if joined:
            args.extend(["--headers", joined])

    if extra_args:
        res_args = validate_args(extra_args)
        if not res_args.ok:
            security_event(logger, "invalid_args", error=res_args.message)
            return _tool_error(res_args.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=url, data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def wpscan_scan_raw(
    *,
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run WPScan with arbitrary CLI args (no shell)."""

    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    res_args = validate_args(args)
    if not res_args.ok:
        return _tool_error(res_args.message or "invalid args")

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            # Raw mode has no structured target; store the arg vector as target for traceability.
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=" ".join(args), data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4561")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m wpscan_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4561

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .harvester_cli import HarvesterNotInstalledError, ensure_api_keys_symlinks, run_theharvester
from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import clamp_int, validate_args, validate_domain, validate_sources


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="theharvester")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


@mcp.tool()
@register_tool
def theharvester_version() -> dict[str, Any]:
    """Return theHarvester version (best-effort via `theHarvester -h`/`--version` style output)."""
    try:
        rr = run_theharvester(domain="example.com", sources="all", limit=1, start=0, extra_args=["-h"], timeout_seconds=30)
        return _tool_ok(
            {"stdout": rr.stdout, "stderr": rr.stderr, "returncode": rr.returncode},
            meta={"command": rr.command},
        )
    except HarvesterNotInstalledError as e:
        security_event(logger, "theharvester_not_installed", error=str(e))
        return _tool_error(str(e))
    except Exception as e:
        return _tool_error("failed to run theHarvester", details={"error": str(e)})


@mcp.tool()
@register_tool
def theharvester_sync_keys() -> dict[str, Any]:
    """
    Ensure mounted api keys are linked into theHarvester's expected locations.
    See upstream: https://github.com/laramies/theHarvester/wiki/Installation
    """
    try:
        res = ensure_api_keys_symlinks()
        return _tool_ok(res)
    except Exception as e:
        return _tool_error("failed to sync api keys", details={"error": str(e)})


@mcp.tool()
@register_tool
def theharvester_run(
    *,
    domain: str,
    sources: str = "all",
    limit: int = 100,
    start: int = 0,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run theHarvester and:
    - save output files into the mounted host dir's `output/` folder (HARVESTER_OUTPUT_DIR, default /data/output)
    - return parsed JSON (if theHarvester produced JSON/JSONL/CSV) plus stdout/stderr

    API key file: mount `/data/keys/api-keys.yaml` as described in upstream wiki:
    https://github.com/laramies/theHarvester/wiki/Installation
    """
    d_res = validate_domain(domain)
    if not d_res.ok:
        security_event(logger, "invalid_domain", domain=domain, error=d_res.message)
        return _tool_error(d_res.message or "invalid domain")

    s_res = validate_sources(sources)
    if not s_res.ok:
        security_event(logger, "invalid_sources", sources=sources, error=s_res.message)
        return _tool_error(s_res.message or "invalid sources")

    try:
        limit = clamp_int(limit, min_value=1, max_value=10_000, name="limit")
        start = clamp_int(start, min_value=0, max_value=10_000_000, name="start")
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(timeout_seconds, min_value=30, max_value=7200, name="timeout_seconds")
    except ValueError as e:
        security_event(logger, "invalid_numeric_option", error=str(e))
        return _tool_error(str(e))

    if extra_args:
        a_res = validate_args(extra_args)
        if not a_res.ok:
            security_event(logger, "invalid_args", error=a_res.message)
            return _tool_error(a_res.message or "invalid extra_args")

    try:
        rr = run_theharvester(
            domain=domain,
            sources=sources,
            limit=limit,
            start=start,
            extra_args=extra_args,
            timeout_seconds=timeout_seconds,
        )
    except HarvesterNotInstalledError as e:
        security_event(logger, "theharvester_not_installed", error=str(e))
        return _tool_error(str(e))
    except Exception as e:
        security_event(logger, "theharvester_run_failed", error=str(e))
        return _tool_error("theHarvester failed", details={"error": str(e)})

    meta = {
        "returncode": rr.returncode,
        "command": rr.command,
        "output_dir": os.getenv("HARVESTER_OUTPUT_DIR", "/data/output"),
    }
    payload = {
        "parsed": rr.parsed,
        "stdout": rr.stdout,
        "stderr": rr.stderr,
        "output_files": rr.output_files,
    }
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="theharvester",
                tool_commandline=rr.command,
                scan_target=domain,
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4562")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m theharvester_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4562

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .paths import exploitdb_dir
from .searchsploit_cli import run_searchsploit, update_exploitdb


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="searchsploit")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


@mcp.tool()
@register_tool
def searchsploit_search(
    terms: list[str],
    *,
    case_insensitive: bool = True,
    max_results_hint: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run Searchsploit against the local ExploitDB clone.
    """
    cleaned = [t.strip() for t in (terms or []) if (t or "").strip()]
    if not cleaned:
        return _tool_error("terms must not be empty")

    flags: list[str] = []
    if case_insensitive:
        flags.append("-i")

    # Searchsploit output is text; we return raw stdout.
    rr = run_searchsploit(cleaned, flags=flags)
    meta = {"returncode": rr.returncode, "command": rr.command, "max_results_hint": max_results_hint}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="searchsploit",
                tool_commandline=rr.command,
                scan_target=" ".join(cleaned),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}
    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def searchsploit_read_exploit(relative_path: str, *, max_bytes: int = 200_000) -> dict[str, Any]:
    """
    Read an exploit file from the local ExploitDB clone (for source inspection).
    """
    rel = (relative_path or "").lstrip("/").strip()
    if not rel:
        return _tool_error("relative_path is required")

    base = exploitdb_dir().resolve()
    target = (base / rel).resolve()
    if not str(target).startswith(str(base) + os.sep):
        security_event(logger, "path_traversal_blocked", relative_path=relative_path)
        return _tool_error("path is outside exploitdb directory")
    if not target.exists() or not target.is_file():
        return _tool_error("file not found", details={"path": str(target)})

    data = target.read_bytes()
    if len(data) > max_bytes:
        data = data[:max_bytes]
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = repr(data[:2000])
    return _tool_ok({"path": str(target), "content": text, "truncated": target.stat().st_size > max_bytes})


@mcp.tool()
@register_tool
def searchsploit_scan_source(
    pattern: str,
    *,
    max_matches: int = 200,
) -> dict[str, Any]:
    """
    Simple source scanning over the exploitdb tree (grep-like).
    Returns file paths containing the pattern (case-insensitive).
    """
    pat = (pattern or "").strip()
    if not pat:
        return _tool_error("pattern is required")
    if len(pat) > 200:
        return _tool_error("pattern too long")

    base = exploitdb_dir()
    matches: list[str] = []
    # naive scan to avoid requiring rg in image; keep bounded
    for p in base.rglob("*"):
        if not p.is_file():
            continue
        try:
            b = p.read_bytes()
        except Exception:
            continue
        if pat.lower().encode() in b.lower():
            matches.append(str(p))
            if len(matches) >= max_matches:
                break

    return _tool_ok({"pattern": pat, "matches": matches, "max_matches": max_matches})


@mcp.tool()
@register_tool
def searchsploit_update() -> dict[str, Any]:
    """
    Update ExploitDB repos inside the running container (git pull).
    """
    return _tool_ok(update_exploitdb())


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4564")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m searchsploit_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4564

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

import httpx
from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .policy import default_engines, requires_opt_in, split_requested_engines
from .validation import validate_engines, validate_query


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="searx")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _searx_url() -> str:
    # IMPORTANT: should remain internal-only (127.0.0.1) inside the container.
    return os.getenv("SEARXNG_URL", "http://127.0.0.1:8080").rstrip("/")

def _timeout_limit_seconds(default: float = 8.0) -> float:
    """
    Default SearXNG backend engine timeout limit (seconds).
    If engines are blocked/unreachable, this prevents long hangs.
    """
    raw = os.getenv("SEARX_TIMEOUT_LIMIT_SECONDS", "").strip()
    if not raw:
        return default
    try:
        v = float(raw)
    except ValueError:
        return default
    if v <= 0:
        return default
    return min(v, 60.0)

def _user_agent() -> str:
    # SearXNG botdetection may block non-browser user agents with 403.
    # Use a reasonable default but allow overrides.
    return os.getenv(
        "SEARX_MCP_USER_AGENT",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    )

def _accept_language(requested_language: str | None) -> str:
    # Keep it simple; SearXNG expects a normal Accept-Language header.
    lang = (requested_language or "").strip()
    if not lang:
        return "en-US,en;q=0.9"
    return f"{lang},en;q=0.8"

def _client_ip() -> str:
    # SearXNG botdetection expects a client IP header in some configurations.
    # Since MCP and SearXNG are co-located in the same container, default to loopback.
    return os.getenv("SEARX_MCP_CLIENT_IP", "127.0.0.1").strip() or "127.0.0.1"


@mcp.tool()
@register_tool
def searx_policy() -> dict[str, Any]:
    """Return the engine privacy policy enforced by this MCP server."""
    return _tool_ok(
        {
            "default_engines": default_engines(),
            "non_private_engines_require_opt_in": sorted(list({"google", "bing", "yahoo", "yandex", "baidu"})),
        }
    )


@mcp.tool()
@register_tool
async def searx_search(
    query: str,
    *,
    engines: list[str] | None = None,
    categories: str | None = None,
    language: str | None = None,
    time_range: str | None = None,
    safesearch: int | None = 1,
    page: int | None = 1,
    max_results: int | None = 25,
    allow_non_private_engines: bool = False,
    timeout_seconds: float | None = 20.0,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Query SearXNG via its internal HTTP API and return JSON.

    Privacy defaults:
    - Uses DuckDuckGo by default
    - Engines like Google/Bing are only allowed when explicitly requested via `engines`
      AND `allow_non_private_engines=true`.
    """

    qv = validate_query(query)
    if not qv.ok:
        security_event(logger, "invalid_query", error=qv.message)
        return _tool_error(qv.message or "invalid query")

    req_engines = split_requested_engines(engines)
    if not req_engines:
        req_engines = default_engines()

    ev = validate_engines(req_engines)
    if not ev.ok:
        security_event(logger, "invalid_engines", error=ev.message)
        return _tool_error(ev.message or "invalid engines")

    needs_opt_in = requires_opt_in(req_engines)
    if needs_opt_in and not allow_non_private_engines:
        security_event(logger, "blocked_non_private_engines", engines=needs_opt_in)
        return _tool_error(
            "non-private engines requested; explicit opt-in required",
            details={"blocked_engines": needs_opt_in, "hint": "set allow_non_private_engines=true"},
        )

    if max_results is not None and (max_results < 1 or max_results > 100):
        return _tool_error("max_results must be between 1 and 100")

    params: dict[str, Any] = {
        "q": query.strip(),
        "format": "json",
        "engines": ",".join(req_engines),
        "pageno": page or 1,
    }
    if categories:
        params["categories"] = categories
    if language:
        params["language"] = language
    if time_range:
        params["time_range"] = time_range
    if safesearch is not None:
        params["safesearch"] = safesearch

    # SearXNG supports limiting backend engine time via `timeout_limit` (seconds).
    # This helps prevent long hangs when engines are blocked/unreachable.
    params["timeout_limit"] = _timeout_limit_seconds()

    url = f"{_searx_url()}/search"

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            headers = {
                "Accept": "application/json",
                "User-Agent": _user_agent(),
                "Accept-Language": _accept_language(language),
                "X-Forwarded-For": _client_ip(),
                "X-Real-IP": _client_ip(),
            }
            resp = await client.get(
                url,
                params=params,
                headers=headers,
            )
            # Some SearXNG instances are configured with `server.method: POST` and may forbid GET searches.
            if resp.status_code == 403:
                resp = await client.post(
                    url,
                    data=params,
                    headers=headers,
                )
    except httpx.TimeoutException as e:
        security_event(
            logger,
            "searx_request_timeout",
            error=str(e),
            internal_url=url,
            timeout_seconds=timeout_seconds,
        )
        return _tool_error(
            "searx request timed out",
            details={
                "internal_url": url,
                "timeout_seconds": timeout_seconds,
                "hint": "check that SearXNG is running and reachable at SEARXNG_URL inside the container (default http://127.0.0.1:8080)",
            },
        )
    except httpx.RequestError as e:
        # Covers DNS errors, connection refused, TLS errors, etc.
        security_event(
            logger,
            "searx_request_error",
            error=str(e),
            error_type=type(e).__name__,
            internal_url=url,
        )
        return _tool_error(
            "failed to reach searx",
            details={
                "internal_url": url,
                "error_type": type(e).__name__,
                "error": str(e),
                "hint": "SearXNG may not be running. Verify the container starts gunicorn successfully and SEARXNG_URL points at the internal bind address.",
            },
        )

    if resp.status_code != 200:
        security_event(logger, "searx_http_error", status=resp.status_code)
        return _tool_error("searx returned non-200", details={"status": resp.status_code, "body": resp.text[:1000]})

    try:
        data = resp.json()
    except Exception as e:
        security_event(
            logger,
            "searx_invalid_json",
            error=str(e),
            status=resp.status_code,
            content_type=resp.headers.get("content-type"),
        )
        return _tool_error(
            "searx returned invalid JSON",
            details={
                "status": resp.status_code,
                "content_type": resp.headers.get("content-type"),
                "body": resp.text[:1000],
            },
        )

    if isinstance(data, dict) and max_results is not None:
        results = data.get("results")
        if isinstance(results, list):
            data["results"] = results[:max_results]

    # Compute which upstream engine(s) actually produced the returned results.
    # SearXNG often annotates each result with `engine` and/or `engines`.
    result_engine_counts: dict[str, int] = {}
    engines_in_results: set[str] = set()
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, list):
            for r in results:
                if not isinstance(r, dict):
                    continue
                eng = r.get("engine")
                if isinstance(eng, str) and eng.strip():
                    k = eng.strip()
                    result_engine_counts[k] = result_engine_counts.get(k, 0) + 1
                    engines_in_results.add(k)
                engs = r.get("engines")
                if isinstance(engs, list):
                    for e in engs:
                        if isinstance(e, str) and e.strip():
                            engines_in_results.add(e.strip())

    meta = {
            # Engines requested/allowed by this MCP server (what we asked SearXNG to use).
            "engines_used": req_engines,
            # Engines that actually show up in the returned result set (derived from SearXNG response).
            "result_engines": sorted(engines_in_results),
            "result_engine_counts": dict(sorted(result_engine_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            "internal_url": url,
            "timeout_limit_seconds": params.get("timeout_limit"),
            "note": "SearXNG is bound to 127.0.0.1 inside the container and is not exposed externally.",
    }

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="searx",
                tool_commandline={"q": params.get("q"), "engines": params.get("engines"), "pageno": params.get("pageno")},
                scan_target=str(params.get("q") or ""),
                data={"result": data, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(data, meta=meta)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4563")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m searx_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4563

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP
from shodan import Shodan
from shodan.exception import APIError

from .env_loader import load_dotenv_if_present
from .filters import describe_filter, list_known_filters
from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import (
    ValidationResult,
    clamp_int,
    validate_filter_expression,
    validate_query,
)

load_dotenv_if_present()

configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="shodan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _validate_list(items: list[str] | None, validator) -> tuple[list[str], list[tuple[str, str]]]:
    if not items:
        return [], []
    ok: list[str] = []
    bad: list[tuple[str, str]] = []
    for x in items:
        x2 = (x or "").strip()
        if not x2:
            continue
        res: ValidationResult = validator(x2)
        if res.ok:
            ok.append(x2)
        else:
            bad.append((x2, res.message or "invalid"))
    return ok, bad


def _env_api_key() -> tuple[str | None, dict[str, Any] | None]:
    """
    Returns (api_key, error_payload). Loads from environment (`SHODAN_API_KEY`).
    The `.env` file is loaded at import-time if present.
    """
    k = os.getenv("SHODAN_API_KEY", "").strip()
    if not k:
        security_event(logger, "missing_api_key_env")
        return None, _tool_error(
            "missing SHODAN_API_KEY",
            details={
                "hint": "Create shodan-mcp-server/.env with SHODAN_API_KEY=... and restart the container",
                "env_var": "SHODAN_API_KEY",
            },
        )
    # Avoid logging the key; only validate basic shape.
    if "\n" in k or "\r" in k or "\x00" in k or len(k) < 16:
        security_event(logger, "invalid_api_key_env_format")
        return None, _tool_error("SHODAN_API_KEY format looks invalid")
    return k, None


def _build_query(
    query: str,
    *,
    filters: list[str] | None,
    country: str | None,
    org: str | None,
    asn: str | None,
    net: str | None,
    port: int | None,
    product: str | None,
    hostname: str | None,
    city: str | None,
) -> tuple[str, list[tuple[str, str]]]:
    parts: list[str] = [query.strip()]
    bad: list[tuple[str, str]] = []

    def maybe_quote(v: str) -> str:
        """
        Preserve quotes if the user already provided them; otherwise wrap in double-quotes.
        Avoid nested f-strings/backslash escapes so this stays valid on Python 3.12+.
        """
        v2 = (v or "").strip()
        if v2.startswith(("\"", "'")):
            return v2
        return f"\"{v2}\""

    def add_expr(expr: str) -> None:
        res = validate_filter_expression(expr)
        if res.ok:
            parts.append(expr)
        else:
            bad.append((expr, res.message or "invalid"))

    if country:
        add_expr(f"country:{country.strip()}")
    if org:
        add_expr(f"org:{maybe_quote(org)}")
    if asn:
        add_expr(f"asn:{asn.strip()}")
    if net:
        add_expr(f"net:{net.strip()}")
    if port is not None:
        add_expr(f"port:{port}")
    if product:
        add_expr(f"product:{maybe_quote(product)}")
    if hostname:
        add_expr(f"hostname:{hostname.strip()}")
    if city:
        add_expr(f"city:{maybe_quote(city)}")

    ok_filters, bad_filters = _validate_list(filters, validate_filter_expression)
    bad.extend(bad_filters)
    parts.extend(ok_filters)

    return " ".join([p for p in parts if p]).strip(), bad


def _summarize_matches(matches: list[dict[str, Any]], *, max_results: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in matches[:max_results]:
        data = (m.get("data") or "").strip()
        if len(data) > 500:
            data = data[:500] + "…"
        loc = m.get("location") or {}
        out.append(
            {
                "ip_str": m.get("ip_str"),
                "port": m.get("port"),
                "transport": m.get("transport"),
                "org": m.get("org"),
                "isp": m.get("isp"),
                "asn": m.get("asn"),
                "hostnames": m.get("hostnames"),
                "domains": m.get("domains"),
                "product": m.get("product"),
                "version": m.get("version"),
                "timestamp": m.get("timestamp"),
                "location": {
                    "country_code": loc.get("country_code"),
                    "country_name": loc.get("country_name"),
                    "region_code": loc.get("region_code"),
                    "city": loc.get("city"),
                    "latitude": loc.get("latitude"),
                    "longitude": loc.get("longitude"),
                },
                "data_excerpt": data,
            }
        )
    return out


@mcp.tool()
@register_tool
def shodan_search(
    query: str,
    filters: list[str] | None = None,
    country: str | None = None,
    org: str | None = None,
    asn: str | None = None,
    net: str | None = None,
    port: int | None = None,
    product: str | None = None,
    hostname: str | None = None,
    city: str | None = None,
    page: int | None = 1,
    max_results: int | None = 25,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Search Shodan using a base `query` and optional filters.

    - If Shodan reports more than 25 results, only the first 25 are returned (configurable via `max_results`).
    - This server reads the Shodan API key from `SHODAN_API_KEY` (loaded from `.env` if present).

    Filters can be provided in two ways:
    - convenience params (country/org/asn/net/port/product/hostname/city)
    - raw filter expressions: `filters=["country:US", "port:443", ...]`
    """
    qv = validate_query(query)
    if not qv.ok:
        security_event(logger, "invalid_query", error=qv.message)
        return _tool_error(qv.message or "invalid query")

    try:
        page2 = clamp_int(int(page or 1), min_value=1, max_value=100, name="page")
    except ValueError as e:
        security_event(logger, "invalid_page", error=str(e))
        return _tool_error(str(e))

    try:
        mr = clamp_int(int(max_results or 25), min_value=1, max_value=25, name="max_results")
    except ValueError as e:
        security_event(logger, "invalid_max_results", error=str(e))
        return _tool_error(str(e))

    if port is not None:
        try:
            port = clamp_int(int(port), min_value=1, max_value=65535, name="port")
        except ValueError as e:
            security_event(logger, "invalid_port", error=str(e))
            return _tool_error(str(e))

    api_key2, err = _env_api_key()
    if err:
        return err

    full_query, bad_filters = _build_query(
        query,
        filters=filters,
        country=country,
        org=org,
        asn=asn,
        net=net,
        port=port,
        product=product,
        hostname=hostname,
        city=city,
    )
    if bad_filters:
        security_event(logger, "invalid_filters", count=len(bad_filters), examples=bad_filters[:5])
        return _tool_error("invalid filter(s) provided", details={"invalid": bad_filters[:50]})

    api = Shodan(api_key2)  # type: ignore[arg-type]

    try:
        res = api.search(full_query, page=page2)
    except APIError as e:
        security_event(logger, "shodan_api_error", error=str(e))
        return _tool_error("Shodan API error", details={"message": str(e)})
    except Exception as e:
        security_event(logger, "shodan_search_error", error=str(e))
        return _tool_error("Shodan search failed", details={"message": str(e)})

    total = int(res.get("total") or 0)
    matches = res.get("matches") or []
    if not isinstance(matches, list):
        matches = []

    summarized = _summarize_matches(matches, max_results=mr)

    meta = {
        "query": full_query,
        "page": page2,
        "total": total,
        "returned_by_shodan_on_this_page": len(matches),
        "shown": len(summarized),
        "note": "If total is larger than shown, paginate with `page=` to view more results.",
    }
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="shodan",
                tool_commandline={"query": full_query, "page": page2, "max_results": mr},
                scan_target=full_query,
                data={"result": summarized, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        summarized,
        meta=meta,
    )


@mcp.tool()
@register_tool
def shodan_filters(name: str | None = None) -> dict[str, Any]:
    """
    List known Shodan filters, or describe one filter by name.

    - `shodan_filters()` returns a list of filters (name/syntax/description).
    - `shodan_filters(name="country")` returns detailed info for a single filter.
    """
    if not name:
        return _tool_ok(list_known_filters(), meta={"count": len(list_known_filters())})

    info = describe_filter(name)
    if not info:
        return _tool_error(
            "unknown filter",
            details={
                "name": (name or "").strip(),
                "hint": "Use shodan_filters() to list known filters; you can still use arbitrary filters via shodan_search(filters=[...]).",
            },
        )
    return _tool_ok(info)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4565")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m shodan_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport in {"stdio"}:
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4565

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info(
            "Starting MCP server",
            extra={"transport": transport, "host": host, "port": port, "path": path or ""},
        )
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info(
        "Starting MCP server with fallback transport",
        extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""},
    )
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from fastmcp import FastMCP
from pymongo import MongoClient
from pymongo.collection import Collection

try:
    from bson import ObjectId
except Exception:  # pragma: no cover
    ObjectId = None  # type: ignore


mcp = FastMCP(name="mongo-mcp")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mongo_collection() -> Collection:
    uri = os.getenv("MONGO_URI", "").strip()
    if not uri:
        raise ValueError("MONGO_URI is not set")
    db_name = (os.getenv("MONGO_DB", "") or "mcp_db").strip() or "mcp_db"
    coll_name = (os.getenv("MONGO_COLLECTION", "") or "results").strip() or "results"
    client = MongoClient(uri, serverSelectionTimeoutMS=3000)
    return client[db_name][coll_name]


def _parse_iso(ts: str) -> datetime:
    # Accept Z suffix or offset-aware ISO.
    s = (ts or "").strip()
    if not s:
        raise ValueError("timestamp is required")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


@mcp.tool()
@register_tool
def mongo_ping() -> dict[str, Any]:
    """Ping MongoDB and return basic connection info."""
    try:
        coll = _mongo_collection()
        coll.database.client.admin.command("ping")
        return _tool_ok({"ok": True, "ts": _utc_now()}, meta={"db": coll.database.name, "collection": coll.name})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def mongo_find(
    *,
    tool_name: str | None = None,
    scan_target: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 50,
    skip: int = 0,
    sort_desc: bool = True,
) -> dict[str, Any]:
    """
    Search `mcp_db.results` for run records by tool_name, scan_target, and/or date_run range.
    Returns documents with `_id` serialized as string.
    """
    try:
        limit = int(limit)
        skip = int(skip)
        if limit < 1 or limit > 1000:
            return _tool_error("limit must be between 1 and 1000")
        if skip < 0 or skip > 1_000_000:
            return _tool_error("skip must be between 0 and 1000000")

        q: dict[str, Any] = {}
        if tool_name:
            q["tool_name"] = (tool_name or "").strip().lower()
        if scan_target:
            q["scan_target"] = (scan_target or "").strip()

        if since or until:
            rng: dict[str, Any] = {}
            if since:
                rng["$gte"] = _parse_iso(since).isoformat()
            if until:
                rng["$lte"] = _parse_iso(until).isoformat()
            q["date_run"] = rng

        coll = _mongo_collection()
        sort_dir = -1 if sort_desc else 1
        cur = coll.find(q).sort("date_run", sort_dir).skip(skip).limit(limit)
        out: list[dict[str, Any]] = []
        for doc in cur:
            doc2 = dict(doc)
            _id = doc2.get("_id")
            doc2["_id"] = str(_id)
            out.append(doc2)
        return _tool_ok(out, meta={"count": len(out), "limit": limit, "skip": skip})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def mongo_get(id: str) -> dict[str, Any]:
    """Get a single result record by MongoDB ObjectId string."""
    try:
        if ObjectId is None:
            return _tool_error("bson ObjectId is unavailable in this environment")
        oid = ObjectId((id or "").strip())
        coll = _mongo_collection()
        doc = coll.find_one({"_id": oid})
        if not doc:
            return _tool_error("not found")
        doc2 = dict(doc)
        doc2["_id"] = str(doc2.get("_id"))
        return _tool_ok(doc2)
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def mongo_stats() -> dict[str, Any]:
    """Return counts grouped by tool_name (top 50) and total count."""
    try:
        coll = _mongo_collection()
        total = coll.count_documents({})
        pipeline = [
            {"$group": {"_id": "$tool_name", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 50},
        ]
        grouped = list(coll.aggregate(pipeline))
        out = [{"tool_name": g.get("_id"), "count": int(g.get("count") or 0)} for g in grouped]
        return _tool_ok({"total": int(total), "by_tool": out})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4570")
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        port = 4570
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .mongo_store import save_to_mongo_result
from .runners import BinaryNotFoundError, run_feroxbuster, run_gobuster
from .wordlists import WordlistError, list_top_level, list_wordlists, resolve_wordlist_for_use, wordlists_root


mcp = FastMCP(name="dirscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _norm_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        raise ValueError("url is required")
    if not (u.startswith("http://") or u.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    return u


def _clamp_int(x: int, *, min_value: int, max_value: int, name: str) -> int:
    try:
        v = int(x)
    except Exception:
        raise ValueError(f"{name} must be an integer")
    if v < min_value or v > max_value:
        raise ValueError(f"{name} must be between {min_value} and {max_value}")
    return v


@mcp.tool()
@register_tool
def wordlists_list(
    subdir: str | None = None,
    limit: int = 5000,
    include_sizes: bool = False,
) -> dict[str, Any]:
    """
    List wordlists under WORDLISTS_ROOT (default: /usr/share/wordlists).

    - Returns only relative names (no full paths).
    - `subdir` is also relative to WORDLISTS_ROOT.
    - `rockyou.txt` is not listed (if a temp copy exists); `rockyou.txt.gz` is listed.
    """
    try:
        limit = _clamp_int(limit, min_value=1, max_value=200000, name="limit")
        # Menu view: no subdir => show first-level categories and root files
        if not subdir:
            top = list_top_level(limit=limit)
            dirs = top.get("dirs") or []
            files = top.get("files") or []
            lines: list[str] = []
            lines.append("Wordlist categories (first-level directories):")
            if not dirs:
                lines.append("  (none)")
            else:
                for i, d in enumerate(dirs, 1):
                    lines.append(f"  {i:>2}. {d}/")
            if files:
                lines.append("")
                lines.append("Wordlists at root:")
                for f in files:
                    lines.append(f"  - {f}")
            lines.append("")
            lines.append("To list a category:")
            lines.append('  call dirscan.wordlists_list {"subdir":"<category>","limit":5000}')

            payload = {"stdout": "\n".join(lines) + "\n", "stderr": ""}
            return _tool_ok(
                payload,
                meta={
                    "wordlists_root": str(wordlists_root()),
                    "dirs_count": len(dirs),
                    "files_count": len(files),
                    "truncated": top.get("truncated"),
                },
            )

        listing = list_wordlists(subdir=subdir, limit=limit, include_sizes=include_sizes)
        lines: list[str] = []
        for item in (listing.get("items") or []):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            if include_sizes and ("bytes" in item):
                b = item.get("bytes")
                if isinstance(b, int):
                    lines.append(f"{name} ({b} bytes)")
                else:
                    lines.append(name)
            else:
                lines.append(name)

        payload = {"stdout": "\n".join(lines) + ("\n" if lines else ""), "stderr": ""}
        return _tool_ok(
            payload,
            meta={
                "wordlists_root": str(wordlists_root()),
                "subdir": subdir,
                "count": listing.get("count"),
                "truncated": listing.get("truncated"),
            },
        )
    except WordlistError as e:
        return _tool_error(str(e), details={"wordlists_root": str(wordlists_root())})


@mcp.tool()
@register_tool
def feroxbuster_scan(
    url: str,
    wordlist: str,
    extensions: list[str] | None = None,
    threads: int = 50,
    depth: int | None = None,
    timeout_seconds: int | None = 900,
    json_output: bool = False,
    extra_args: list[str] | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run feroxbuster against a target URL using a wordlist under WORDLISTS_ROOT.

    `wordlist` must be a relative path under WORDLISTS_ROOT, e.g. `dirb/common.txt` or `rockyou.txt.gz`.
    If `wordlist` is `rockyou.txt.gz`, it will be decompressed once per server session (warning + progress).
    """
    try:
        u = _norm_url(url)
        threads2 = _clamp_int(threads, min_value=1, max_value=2000, name="threads")
        if depth is not None:
            depth = _clamp_int(depth, min_value=0, max_value=50, name="depth")
    except ValueError as e:
        return _tool_error(str(e))

    try:
        wl_path, progress = resolve_wordlist_for_use(wordlist)
    except WordlistError as e:
        return _tool_error(str(e), details={"wordlists_root": str(wordlists_root())})

    args: list[str] = ["-u", u, "-w", str(wl_path), "-t", str(threads2)]
    if depth is not None:
        args.extend(["--depth", str(depth)])
    if extensions:
        exts = [x.strip().lstrip(".") for x in extensions if (x or "").strip()]
        if exts:
            args.extend(["-x", ",".join(exts)])
    if json_output:
        args.append("--json")
    if extra_args:
        # safe wrapper: we don't allow obvious file-write flags here
        blocked = {"-o", "--output", "--config", "--stdin"}
        if any(a in blocked for a in extra_args):
            return _tool_error("extra_args contains blocked flags (use feroxbuster_scan_raw with i_acknowledge_risk=true)")
        args.extend(extra_args)

    try:
        rr = run_feroxbuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install feroxbuster or set FEROXBUSTER_BIN"})

    stdout = rr.stdout
    if progress:
        stdout = "\n".join(progress) + "\n\n" + stdout

    payload: dict[str, Any] = {"stdout": stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command, "wordlists_root": str(wordlists_root()), "wordlist_used": str(wl_path)}

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(
                tool_name="feroxbuster",
                tool_commandline=rr.command,
                scan_target=u,
                data={"result": payload, "meta": meta},
            )
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def gobuster_scan(
    url: str,
    wordlist: str,
    extensions: list[str] | None = None,
    threads: int = 50,
    timeout_seconds: int | None = 900,
    extra_args: list[str] | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run gobuster dir against a target URL using a wordlist under WORDLISTS_ROOT.

    `wordlist` must be a relative path under WORDLISTS_ROOT, e.g. `dirb/common.txt` or `rockyou.txt.gz`.
    If `wordlist` is `rockyou.txt.gz`, it will be decompressed once per server session (warning + progress).
    """
    try:
        u = _norm_url(url)
        threads2 = _clamp_int(threads, min_value=1, max_value=2000, name="threads")
    except ValueError as e:
        return _tool_error(str(e))

    try:
        wl_path, progress = resolve_wordlist_for_use(wordlist)
    except WordlistError as e:
        return _tool_error(str(e), details={"wordlists_root": str(wordlists_root())})

    args: list[str] = ["dir", "-u", u, "-w", str(wl_path), "-t", str(threads2)]
    if extensions:
        exts = [x.strip().lstrip(".") for x in extensions if (x or "").strip()]
        if exts:
            args.extend(["-x", ",".join(exts)])
    if extra_args:
        blocked = {"-o", "--output", "--no-color"}  # keep output on stdout; allow colors via cli if desired
        if any(a in blocked for a in extra_args):
            return _tool_error("extra_args contains blocked flags (use gobuster_scan_raw with i_acknowledge_risk=true)")
        args.extend(extra_args)

    try:
        rr = run_gobuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install gobuster or set GOBUSTER_BIN"})

    stdout = rr.stdout
    if progress:
        stdout = "\n".join(progress) + "\n\n" + stdout

    payload: dict[str, Any] = {"stdout": stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command, "wordlists_root": str(wordlists_root()), "wordlist_used": str(wl_path)}

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(
                tool_name="gobuster",
                tool_commandline=rr.command,
                scan_target=u,
                data={"result": payload, "meta": meta},
            )
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def feroxbuster_scan_raw(
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run feroxbuster with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]
    try:
        rr = run_feroxbuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install feroxbuster or set FEROXBUSTER_BIN"})
    payload = {"stdout": rr.stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(tool_name="feroxbuster", tool_commandline=rr.command, scan_target="", data={"result": payload, "meta": meta})
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}
    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def gobuster_scan_raw(
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run gobuster with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]
    try:
        rr = run_gobuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install gobuster or set GOBUSTER_BIN"})
    payload = {"stdout": rr.stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(tool_name="gobuster", tool_commandline=rr.command, scan_target="", data={"result": payload, "meta": meta})
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}
    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    if transport == "stdio":
        mcp.run(transport="stdio")
        return
    # Optional HTTP transports
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4605"))
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="pentest-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

_NMAP_PORT_LINE_RE = re.compile(r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)\s*$")
_RUSTSCAN_OPEN_RE = re.compile(r"^Open\s+(?P<host>[^:]+):(?P<port>\d{1,5})\s*$")


def _parse_jsonl(stdout: str, *, max_items: int = 500) -> dict[str, Any]:
    """
    Best-effort parse of JSONL output into a small list for Mongo-friendly storage.
    """
    items: list[dict[str, Any]] = []
    total = 0
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        total += 1
        if len(items) >= max_items:
            continue
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                items.append(obj)
        except Exception:
            continue
    return {"parsed_count": total, "sample": items, "sample_limit": max_items}


def _parse_nmap_ports(stdout: str) -> list[dict[str, Any]]:
    """
    Very small parser for Nmap's human output table (best-effort).
    """
    ports: list[dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        m = _NMAP_PORT_LINE_RE.match(line.strip())
        if not m:
            continue
        try:
            p = int(m.group("port"))
        except Exception:
            continue
        ports.append(
            {
                "port": p,
                "proto": m.group("proto"),
                "state": m.group("state"),
                "service": m.group("service"),
            }
        )
    return ports


def _parse_rustscan_open_ports(stdout: str, *, max_items: int = 500) -> dict[str, Any]:
    """
    Parse lines like 'Open 192.168.1.1:443' from RustScan output (best-effort).
    """
    out: list[dict[str, Any]] = []
    total = 0
    for line in (stdout or "").splitlines():
        m = _RUSTSCAN_OPEN_RE.match(line.strip())
        if not m:
            continue
        total += 1
        if len(out) >= max_items:
            continue
        try:
            port = int(m.group("port"))
        except Exception:
            continue
        out.append({"host": m.group("host"), "port": port})
    return {"parsed_count": total, "sample": out, "sample_limit": max_items}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = 300,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Naabu against targets with common structured options (safe wrapper)."""
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    jsonl = _parse_jsonl(rr.stdout)
    if jsonl.get("sample"):
        payload["jsonl"] = jsonl
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = 300,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Naabu with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    jsonl = _parse_jsonl(rr.stdout)
    if jsonl.get("sample"):
        payload["jsonl"] = jsonl
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Nmap against targets (structured wrapper)."""
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    parsed_ports = _parse_nmap_ports(rr.stdout)
    if parsed_ports:
        payload["parsed"] = {"ports": parsed_ports, "count": len(parsed_ports)}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    args: list[str],
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = 900,
) -> dict[str, Any]:
    """Run Nmap with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run RustScan against targets with structured options (optionally passing Nmap args)."""
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    parsed = _parse_rustscan_open_ports(rr.stdout)
    if parsed.get("sample"):
        payload["parsed"] = {"open_ports": parsed}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
    timeout_seconds: int | None = 900,
) -> dict[str, Any]:
    """Run RustScan with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Naabu, RustScan, and Nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    # Only require explicit risk acknowledgement when the caller provides "extra" args
    # that may enable aggressive scanning or additional behaviors (e.g., nmap scripts).
    risky_tokens: set[str] = {
        "--script",
        "--script-args",
        "--script-help",
        "-o",
        "-oA",
        "-oG",
        "-oN",
        "-oX",
        "--resume",
    }
    any_extra = bool(naabu_extra_args) or bool(rustscan_extra_args) or bool(nmap_extra_args)
    style_args = [a.strip() for a in nmap_style_args2 if isinstance(a, str)]
    needs_ack = any_extra or any(a in risky_tokens for a in style_args)
    if needs_ack:
        ok, err = _require_ack(i_acknowledge_risk)
        if not ok:
            return err  # type: ignore[return-value]

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        naabu_payload: dict[str, Any] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
        jsonl = _parse_jsonl(rr1.stdout)
        if jsonl.get("sample"):
            naabu_payload["parsed"] = {"jsonl": jsonl}
        results["naabu"] = naabu_payload
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        rust_payload: dict[str, Any] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
        parsed = _parse_rustscan_open_ports(rr2.stdout)
        if parsed.get("sample"):
            rust_payload["parsed"] = {"open_ports": parsed}
        results["rustscan"] = rust_payload
    except Exception as e:
        results["rustscan"] = {"error": str(e)}
        nmap_notes = []

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        nmap_payload: dict[str, Any] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
        parsed_ports = _parse_nmap_ports(rr3.stdout)
        if parsed_ports:
            nmap_payload["parsed"] = {"ports": parsed_ports, "count": len(parsed_ports)}
        results["nmap"] = nmap_payload
    except Exception as e:
        results["nmap"] = {"error": str(e)}
        nmap_notes2 = []

    meta: dict[str, Any] = {
        "invalid_targets": bad[:50],
        "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
        "nmap_coercion": (nmap_notes + nmap_notes2),
    }

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            tool_commandline = {
                "naabu": results.get("naabu", {}).get("command") if isinstance(results.get("naabu"), dict) else None,
                "rustscan": results.get("rustscan", {}).get("command") if isinstance(results.get("rustscan"), dict) else None,
                "nmap": results.get("nmap", {}).get("command") if isinstance(results.get("nmap"), dict) else None,
            }
            saved = save_to_mongo_result(
                tool_name="portscan_all",
                tool_commandline=tool_commandline,
                scan_target=",".join(ok_targets),
                data={"result": results, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(results, meta=meta)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4598")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pentest_mcp_server.server` works in Cursor without extra env.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4598

    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

### Root cause
You’re on **FastMCP 2.14.1**, and it has a schema-generation quirk: when your tool functions use `from __future__ import annotations`, the annotations are **strings**, and FastMCP incorrectly marks **nullable fields as required** even if they default to `None`.

I reproduced it in your exact Standalone venv and verified the fix.

### Fix implemented (so nullable params become truly optional)
I updated the `register_tool()` decorator across your servers to “de-stringify” annotations **before** FastMCP wraps the function:

- It calls `typing.get_type_hints(...)`
- Then writes `fn.__annotations__ = dict(hints)` (best-effort)

This makes FastMCP generate the correct required-list.

### Verified (in your Standalone_Build runtime)
Running in `Standalone_Build/.venv`, `pd_run` now has:

- **required**: `['tool']`
- `args`, `stdin_lines`, `timeout_seconds`, `save` are **optional** (default `None`)

### What you need to do in Cursor (important)
Because Cursor caches tool schemas from the running stdio process, **restart the `pdtm` MCP server** after pulling these changes:

- In Cursor’s MCP servers UI: **Restart** the `pdtm` server (or toggle off/on).
- Then re-run: **`describe pdtm.pd_run`** (or however Cursor labels it). You should now see only `tool` required.

If you want, paste the output of the new `describe …` and I’ll confirm it’s correct.

---

**User**

In the "describe pdtm.pd_run" you mention "The tool must be one of `pd_supported_tools()`." - can you please add a section within the "describe pdtm.pd_run" to list the supported Project Discovery tools?

---

**Cursor**

Plan: I’ll update the `pdtm` server so `pd_run`’s tool description automatically appends a “Supported tools” section (derived from the `_SUPPORTED_TOOLS` allowlist). Because this happens inside `register_tool()` before FastMCP wraps the function, it will show up directly in Cursor’s `describe pdtm.pd_run`.

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nTip: You can also call `pd_supported_tools()` to retrieve this list programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nTip: You can also call `pd_supported_tools()` to retrieve this list programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

### Change made
`describe pdtm.pd_run` will now include a **“Supported tools (allowlist)”** section listing the currently supported ProjectDiscovery tools.

Verified in your `Standalone_Build/.venv` runtime, the description now contains:

- dnsx
- httpx
- katana
- naabu
- nuclei
- subfinder
- tlsx

### What you need to do
Restart the `pdtm` MCP server (since Cursor caches tool descriptions), then run **`describe pdtm.pd_run`** again and you should see that new section.

---

**User**

For "describe pdtm.pd_run" I am seeing the tools support - fantastic, but you also mention "Tip: You can also call `pd_supported_tools()` to retrieve this list programmatically." - is there a way I can do this from within the "pentest-cli" interface?

---

**Cursor**

Plan: I’ll quickly inspect `Standalone_Build/pentest-cli` to see how it talks to MCP servers (stdio subprocess vs HTTP), then I’ll tell you the exact command (or subcommand) to call the `pdtm.pd_supported_tools` tool from that interface, and what output to expect.

Yes — in `pentest-cli` you can call it directly, same as any other MCP tool.

### From the `pentest-cli` prompt
Run:

```text
pentest> call pdtm.pd_supported_tools {}
```

Or if you want the full MCP JSON response:

```text
pentest> call-json pdtm.pd_supported_tools {}
```

### Quick discovery tip
If you’re not sure of the exact tool name:

```text
pentest> tools pdtm
```

```plaintext
pentest> call pdtm.pd_supported_tools {}
```

```plaintext
pentest> call-json pdtm.pd_supported_tools {}
```

```plaintext
pentest> tools pdtm
```

---

**User**

Is it possible for me to see what the options/required fields would be for a pdtm tool? For example, how can I see what would be required if I were to run 'call pdtm.pd_run {"tool": "nuclei"}'?

---

**Cursor**

Yes—use `describe` / `describe-json` in `pentest-cli`.

### Human-friendly (what to type)
```text
pentest> describe pdtm.pd_run
```

### Raw schema (shows required vs optional)
```text
pentest> describe-json pdtm.pd_run
```

For your example, you can confirm that **only `tool` is required** by checking the JSON schema’s `required` list; then this call is valid:

```text
pentest> call pdtm.pd_run {"tool":"nuclei"}
```

```plaintext
pentest> describe pdtm.pd_run
```

```plaintext
pentest> describe-json pdtm.pd_run
```

```plaintext
pentest> call pdtm.pd_run {"tool":"nuclei"}
```

---

**User**

Actually, I am asking about required flags/inputs for the "nuclei" tool - is there a means to see what is required to run nuclei and what other options are available? Perhaps, doing "describe pdtm.pd_run.nuclei" or another tool name that will show what options are required or optional to run nuclei. And also, how would I pass those "nuclei" from the pdtm.pd_run command - I believe that would be the "args" JSON field, but just needing to make sure and what those args would be for nuclei (and other pdtm tools)

---

**Cursor**

No — there’s **no** `pdtm.pd_run.nuclei` sub-tool. `pdtm.pd_run` is a **generic wrapper**, so “what flags exist / what’s required” is whatever the underlying **ProjectDiscovery CLI** requires.

### How to see Nuclei’s flags + what’s required (from `pentest-cli`)
Run the tool’s built-in help via **raw mode** (so the server doesn’t auto-append `-jsonl`):

```text
pentest> call pdtm.pd_run_raw {"tool":"nuclei","args":["-h"],"i_acknowledge_risk":true}
```

That prints Nuclei’s full CLI usage (required/optional flags).

You can do the same for other PD tools:

```text
pentest> call pdtm.pd_run_raw {"tool":"httpx","args":["-h"],"i_acknowledge_risk":true}
pentest> call pdtm.pd_run_raw {"tool":"naabu","args":["-h"],"i_acknowledge_risk":true}
```

### How to pass Nuclei options to `pdtm.pd_run`
Yes: you pass them via the **`args`** JSON field (a list of CLI tokens), and optionally targets via either CLI flags or `stdin_lines`.

Example (targets via `-u`):

```text
pentest> call pdtm.pd_run {"tool":"nuclei","args":["-u","https://example.com","-severity","high"]}
```

Example (targets via stdin pipeline):

```text
pentest> call pdtm.pd_run {"tool":"nuclei","stdin_lines":["https://example.com"],"args":["-severity","high"]}
```

Notes:
- `pdtm.pd_run` (safe mode) **blocks some file/config output flags**; if you need everything, use `pdtm.pd_run_raw`.
- `pdtm.pd_run` may auto-add structured output flags (e.g. `-jsonl` for nuclei) unless you specify your own.

```plaintext
pentest> call pdtm.pd_run_raw {"tool":"nuclei","args":["-h"],"i_acknowledge_risk":true}
```

```plaintext
pentest> call pdtm.pd_run_raw {"tool":"httpx","args":["-h"],"i_acknowledge_risk":true}
pentest> call pdtm.pd_run_raw {"tool":"naabu","args":["-h"],"i_acknowledge_risk":true}
```

```plaintext
pentest> call pdtm.pd_run {"tool":"nuclei","args":["-u","https://example.com","-severity","high"]}
```

```plaintext
pentest> call pdtm.pd_run {"tool":"nuclei","stdin_lines":["https://example.com"],"args":["-severity","high"]}
```

---

**User**

Can you please ensure all of the changes made today are documented appropriately , be sure to include your description on how to see the args required for a specific tool. Also, put that information on how to get the help output into the "describe pdtm.pd_run" output.

---

**Cursor**

Plan: I’ll update the docs in the right places (pdtm server README + Standalone_Build docs) to capture today’s changes: wordlists are local-only, nullable tool params are now truly optional, and FastMCP required/nullable schema bug is fixed. Then I’ll also extend `describe pdtm.pd_run` itself to include a “How to discover per-tool flags” section with the `pd_run_raw -h` examples.

Nice — we’ll document this in three places so it’s discoverable where you’ll actually look: the `pdtm` README(s), the `pentest-cli` README, and directly inside the `describe pdtm.pd_run` output (so you don’t have to remember any of this later). Next I’ll patch the `pd_run` doc enrichment and then add concise “how to get `-h` output + pass args” examples to the docs.

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help via raw mode:\n\n"
            + '- `pd_run_raw` with `args=["-h"]` (requires `i_acknowledge_risk=true`)\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"], "i_acknowledge_risk": true }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help via raw mode:\n\n"
            + '- `pd_run_raw` with `args=["-h"]` (requires `i_acknowledge_risk=true`)\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"], "i_acknowledge_risk": true }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```markdown
## pdtm-mcp-server

An MCP server that exposes **multiple ProjectDiscovery tools** (installed via **PDTM**) behind a single FastMCP server.

- PDTM repo: [projectdiscovery/pdtm](https://github.com/projectdiscovery/pdtm)
- ProjectDiscovery OSS docs: [ProjectDiscovery Open Source Tools](https://docs.projectdiscovery.io/opensource)

This server listens on **port 4599** inside the container and is intended to be run under **Podman** (works with Docker too).

### Tools exposed

- **`pd_run`**: Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).
- **`pd_run_raw`**: Run a supported ProjectDiscovery tool with arbitrary args (requires `i_acknowledge_risk=true`).
- **`pd_smart`**: Accept a vague intent (e.g. “find subdomains for example.com”) and choose a tool + flags.

### Discover per-tool flags (required/optional) and pass them into `pd_run`

`pd_run` is a generic wrapper: the "required flags" are whatever the underlying ProjectDiscovery tool requires.

- To see a tool’s native help/usage (flags, defaults, required inputs), run `-h` via raw mode:

```json
{
  "tool": "nuclei",
  "args": ["-h"],
  "i_acknowledge_risk": true
}
```

- To pass flags/options into a tool, use `args` (a list of CLI tokens). Example:

```json
{
  "tool": "nuclei",
  "args": ["-u", "https://example.com", "-severity", "high"]
}
```

### Cursor (MCP stdio)

Cursor MCP “command” servers communicate over **stdio**. Use one of the following:

- **Podman stdio wrapper**: run `./cursor-stdio.sh` (after building the image).
- **mcp.json env**: ensure `MCP_TRANSPORT=stdio` is set for this server.

### Examples

**Subdomains (explicit):**

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-d", "example.com"]
}
```

**Subdomains (smart):**

```json
{
  "request": "Please find me the subdomains for example.com"
}
```

**Save to a file in `/data/output`:**

```json
{
  "tool": "httpx",
  "args": ["-silent", "-sc", "-title"],
  "stdin_lines": ["https://example.com"],
  "save": { "type": "file", "filename": "httpx-example.json" }
}
```

**Save to MongoDB:**

```json
{
  "request": "crawl https://example.com",
  "save": { "type": "mongo", "mongo_db": "recon", "mongo_collection": "katana_runs" }
}
```

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-all", "-d", "warnermusic.com"],
  "timeout_seconds": 600,
  "save": { "type": "file" }
}

# List
{ "prefix": "warnermusic.com-2025-12-25", "recursive": true }

# Read/Download
{ "path": "warnermusic.com-2025-12-25/subfinder.json", "max_bytes": 2000000, "as_base64": false }
```

### Result persistence

- **Files**: save to `/data/output` (mount a Podman volume; recommended)
- **MongoDB**: save to a database/collection (configure via env)

### Podman run (HTTP MCP on port 4599)

Build:

```bash
podman build -t pdtm-mcp-server -f Containerfile .
```

Run (expose port 4599 and persist outputs):

```bash
podman volume create pdtm_data
podman run --rm -p 4599:4599 -v pdtm_data:/data/output pdtm-mcp-server
```

### File layout in the Podman volume (recommended)

When saving with `{"save": {"type": "file"}}`, the server writes into `OUTPUT_DIR` (default `/data/output`).

- If `save.run_dir` is not provided, the server will auto-create (or reuse) a directory named:
  - `<target>-YYYY-MM-DD` (example: `wmg.com-2025-12-25`)
- If `save.filename` is not provided, the server defaults to:
  - `<tool>.json` (example: `subfinder.json`)
- If a file name already exists, the server will **not overwrite** it; it will append:
  - `-HH_MM_SS` (and a counter if needed)

Example save:

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-d", "wmg.com"],
  "timeout_seconds": 600,
  "save": { "type": "file" }
}
```

### Browsing / downloading saved results (via MCP)

- **`pd_results_list`**: list files/dirs under `/data/output` (Podman volume)
- **`pd_results_read`**: read a file from `/data/output` (text or base64) — this is the supported “download” path
- **`pd_results_export`**: copy a file from `/data/output` into `/data/downloads` (requires a host bind-mount)

To export directly into your host `~/Downloads` folder, bind-mount it to `/data/downloads` when launching the container.

- **Via `cursor-stdio.sh`**:

```bash
PDTM_OUTPUT_VOLUME=pdtm_data PDTM_DOWNLOADS_DIR="$HOME/Downloads" ./cursor-stdio.sh
```

- **Via `mcp.json`** (example on macOS):

```json
"-v",
"/Users/pkincaid/Downloads:/data/downloads"
```

### Note on transports

- **stdio**: for Cursor (set `MCP_TRANSPORT=stdio`)
- **HTTP**: for networked use (set `MCP_TRANSPORT=streamable-http`, default in the Containerfile)

### MongoDB configuration

Set these env vars when running the container:

- `MONGO_URI` (example: `mongodb://mongo:27017`)
- `MONGO_DB` (default: `pdtm_mcp`)

### Notes / references

- PDTM is ProjectDiscovery’s tool manager: [projectdiscovery/pdtm](https://github.com/projectdiscovery/pdtm)
- General docs for ProjectDiscovery OSS tools: [ProjectDiscovery Open Source Tools](https://docs.projectdiscovery.io/opensource)
- Recon workflow inspiration (3rd-party article): `https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a`


## mcp.json

```
{
  "mcpServers": {
    "project_discovery": {
      "command": "podman",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e",
        "MCP_TRANSPORT=stdio",
        "-v",
        "pdtm_data:/data/output",
        "--name",
        "pdtm-mcp-stdio",
        "pdtm-mcp-server"
      ]
    }
  }
}
```
```

```markdown
## pdtm-mcp-server

An MCP server that exposes **multiple ProjectDiscovery tools** (installed via **PDTM**) behind a single FastMCP server.

- PDTM repo: [projectdiscovery/pdtm](https://github.com/projectdiscovery/pdtm)
- ProjectDiscovery OSS docs: [ProjectDiscovery Open Source Tools](https://docs.projectdiscovery.io/opensource)

In `Standalone_Build`, this server is intended to be launched locally via **stdio** and called from `pentest-cli` as `pdtm.<tool>`.

### Tools exposed

- **`pd_run`**: Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).
- **`pd_run_raw`**: Run a supported ProjectDiscovery tool with arbitrary args (requires `i_acknowledge_risk=true`).
- **`pd_smart`**: Accept a vague intent (e.g. “find subdomains for example.com”) and choose a tool + flags.

### Cursor (MCP stdio)

Cursor MCP “command” servers communicate over **stdio**. In the standalone build, `Standalone_Build/mcp.json` already sets `MCP_TRANSPORT=stdio` and launches this server via `Standalone_Build/run-mcp-stdio.sh`.

### Run (stdio)

From `Standalone_Build/`:

```bash
./run-mcp-stdio.sh pdtm_mcp_server.server
```

### Call from `pentest-cli`

```text
pentest> call pdtm.pd_supported_tools {}
pentest> call pdtm.pd_smart {"request":"find subdomains for example.com","domain":"example.com"}
```

### Discover per-tool flags (required/optional) and pass them into `pd_run`

`pd_run` is a generic wrapper: the "required flags" are whatever the underlying ProjectDiscovery tool requires.

From `pentest-cli`, the easiest way to see a tool’s native help/usage (flags, defaults, required inputs) is:

```text
pentest> call pdtm.pd_run_raw {"tool":"nuclei","args":["-h"],"i_acknowledge_risk":true}
```

Then pass the tool flags via `args`:

```text
pentest> call pdtm.pd_run {"tool":"nuclei","args":["-u","https://example.com","-severity","high"]}
```

### Examples

**Subdomains (explicit):**

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-d", "example.com"]
}
```

**Subdomains (smart):**

```json
{
  "request": "Please find me the subdomains for example.com"
}
```

**Save to a file in `/data/output`:**

```json
{
  "tool": "httpx",
  "args": ["-silent", "-sc", "-title"],
  "stdin_lines": ["https://example.com"],
  "save": { "type": "file", "filename": "httpx-example.json" }
}
```

**Save to MongoDB:**

```json
{
  "request": "crawl https://example.com",
  "save": { "type": "mongo", "mongo_db": "recon", "mongo_collection": "katana_runs" }
}
```

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-all", "-d", "warnermusic.com"],
  "timeout_seconds": 600,
  "save": { "type": "file" }
}

# List
{ "prefix": "warnermusic.com-2025-12-25", "recursive": true }

# Read/Download
{ "path": "warnermusic.com-2025-12-25/subfinder.json", "max_bytes": 2000000, "as_base64": false }
```

### Result persistence

- **Files**: save to `OUTPUT_DIR` (configure via env; in `Standalone_Build` this is typically set via `Standalone_Build/.env`)
- **MongoDB**: save to a database/collection (configure via env / `Standalone_Build/.env`)

### Podman run (reference)

Build:

```bash
podman build -t pdtm-mcp-server -f Containerfile .
```

Run (expose port 4599 and persist outputs):

```bash
podman volume create pdtm_data
podman run --rm -p 4599:4599 -v pdtm_data:/data/output pdtm-mcp-server
```

### File layout in `OUTPUT_DIR` (recommended)

When saving with `{"save": {"type": "file"}}`, the server writes into `OUTPUT_DIR`.

- If `save.run_dir` is not provided, the server will auto-create (or reuse) a directory named:
  - `<target>-YYYY-MM-DD` (example: `wmg.com-2025-12-25`)
- If `save.filename` is not provided, the server defaults to:
  - `<tool>.json` (example: `subfinder.json`)
- If a file name already exists, the server will **not overwrite** it; it will append:
  - `-HH_MM_SS` (and a counter if needed)

Example save:

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-d", "wmg.com"],
  "timeout_seconds": 600,
  "save": { "type": "file" }
}
```

### Browsing / downloading saved results (via MCP)

- **`pd_results_list`**: list files/dirs under `OUTPUT_DIR`
- **`pd_results_read`**: read a file from `OUTPUT_DIR` (text or base64)
- **`pd_results_export`**: copy a file from `OUTPUT_DIR` into `DOWNLOAD_DIR` (requires a host bind-mount when containerized)

To export directly into your host `~/Downloads` folder, bind-mount it to `/data/downloads` when launching the container.

- **Via `cursor-stdio.sh`**:

```bash
PDTM_OUTPUT_VOLUME=pdtm_data PDTM_DOWNLOADS_DIR="$HOME/Downloads" ./cursor-stdio.sh
```

- **Via `mcp.json`** (example on macOS):

```json
"-v",
"/Users/pkincaid/Downloads:/data/downloads"
```

### Note on transports

- **stdio**: for Cursor (set `MCP_TRANSPORT=stdio`)
- **HTTP**: for networked use (set `MCP_TRANSPORT=streamable-http`, default in the Containerfile)

### MongoDB configuration

Set these env vars when running the container:

- `MONGO_URI` (example: `mongodb://mongo:27017`)
- `MONGO_DB` (default: `pdtm_mcp`)

### Notes / references

- PDTM is ProjectDiscovery’s tool manager: [projectdiscovery/pdtm](https://github.com/projectdiscovery/pdtm)
- General docs for ProjectDiscovery OSS tools: [ProjectDiscovery Open Source Tools](https://docs.projectdiscovery.io/opensource)
- Recon workflow inspiration (3rd-party article): `https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a`


## mcp.json

```
{
  "mcpServers": {
    "project_discovery": {
      "command": "podman",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e",
        "MCP_TRANSPORT=stdio",
        "-v",
        "pdtm_data:/data/output",
        "--name",
        "pdtm-mcp-stdio",
        "pdtm-mcp-server"
      ]
    }
  }
}
```
```

```markdown
# pentest-cli

Interactive terminal CLI for calling MCP tools over **stdio** using a local `mcp.json`.

## Install (shared venv)

From `Standalone_Build/`:

```bash
source .venv/bin/activate
pip install -e ./pentest-cli
```

## Run

```bash
pentest-cli
```

## Startup behavior

- By default, `pentest-cli` **autoloads (starts) all MCP servers** from `Standalone_Build/mcp.json` so all tools are immediately available.
- To disable autoloading (start servers only when you explicitly `connect`), run: `pentest-cli --no-autoload-all`
- Server stderr logs (FastMCP banners, logs, etc.) are redirected to: `Standalone_Build/logs/*.stderr.log`

## Commands

- `servers` — list configured servers from `Standalone_Build/mcp.json`
- `connect <server>` — connect to a server (optional; autoload already connects everything by default)
- `status` — show current connection (mostly useful when using `connect`)
- `tools [filter]` — list tools across all servers (shows `server.tool` and hides `list_tools`/`describe_tool`)
- `describe <server.tool>` — human-friendly help for a tool (inputs + example call)
- `describe-json <server.tool>` — raw tool schema (MCP JSON schema)
- `call <server.tool> <json|@file>` — call a tool (prints stdout/stderr by default)
- `call-json <server.tool> <json|@file>` — call a tool and print full MCP JSON response
- `mongo-use <db> <collection>` — set default db/collection for CLI Mongo queries
- `mongo-find-one <json|@file>` — run `find_one(filter)` against default db/collection
- `mongo-find <json|@file> [limit=N]` — run `find(filter).limit(N)` against default db/collection
- `quit` / `exit` — leave the shell

## Examples (portscan coordinator)

List tools:

```text
pentest> tools
pentest> tools scan
```

Describe a tool:

```text
pentest> describe portscan.nmap_scan
pentest> describe-json portscan.nmap_scan
```

Nmap scan (ports 1-1024):

```text
pentest> call portscan.nmap_scan {"targets":["192.168.1.1"],"args":["-p","1-1024","-sT"],"force_unprivileged":true}
```

RustScan scan (ports 1-1024):

```text
pentest> call portscan.rustscan_scan {"targets":["192.168.1.1"],"ports":"1-1024"}
```

All-in-one port scanning (naabu + rustscan + nmap):

```text
pentest> call portscan.portscan_all {"targets":["192.168.1.1"],"nmap_style_args":["-p","1-1024","-sT"]}
```

Notes:
- By default, `pentest-cli` injects `save={"type":"mongo"}` for tools that support saving (unless you run with `--no-save-mongo`).
- Ensure `MONGO_URI` is set and MongoDB is running, or you’ll see `saved: failed (...)`.

## Examples (other servers)

All tools are called the same way: `server.tool`.

### Shodan

```text
pentest> tools shodan
pentest> describe shodan.shodan_search
pentest> call shodan.shodan_search {"query":"org:\"Example Corp\"","max_results":5}
```

### Searchsploit

```text
pentest> call searchsploit.searchsploit_search {"terms":["wordpress","plugin"],"case_insensitive":true}
```

### theHarvester

```text
pentest> call theharvester.theharvester_run {"domain":"example.com","sources":"all","limit":200,"start":0}
```

### WPScan

```text
pentest> call wpscan.wpscan_scan {"url":"https://example.com","enumerate":"vp,vt,cb,u","stealthy":true}
```

### SearXNG

```text
pentest> call searx.searx_search {"query":"example.com exposed admin","max_results":10}
```

### ProjectDiscovery tools (via `pdtm`)

`pdtm.pd_run` is a generic wrapper around ProjectDiscovery CLIs (e.g. `nuclei`, `httpx`, `naabu`).
To see what flags a specific tool supports (and what it requires), run its native help:

```text
pentest> call pdtm.pd_run_raw {"tool":"nuclei","args":["-h"],"i_acknowledge_risk":true}
```

Then pass the flags you want via `args`:

```text
pentest> call pdtm.pd_run {"tool":"nuclei","args":["-u","https://example.com","-severity","high"]}
```

## MongoDB query examples (CLI-side, via pymongo)

Set default db/collection for queries:

```text
pentest> mongo-use mcp_db results
```

Find one recent run for a tool:

```text
pentest> mongo-find-one {"tool_name":"nmap"}
```

Find many (limit 5):

```text
pentest> mongo-find {"tool_name":"portscan_all"} limit=5
```

## Config and .env

`pentest-cli` uses:
- `Standalone_Build/mcp.json` for server definitions
- `Standalone_Build/.env` (auto-loaded, unless `PENTEST_CLI_NO_DOTENV` is set) for variables like `MONGO_URI`, `MONGO_DB`, `MONGO_COLLECTION`

## Config discovery

By default, `pentest-cli` auto-discovers `Standalone_Build/mcp.json` even when run outside the repo.

To force a specific config:

- `pentest-cli --config "/Users/pkincaid/Documents/bin/joesgarage.ai - AI Projects/MCP_Servers/Standalone_Build/mcp.json"`
- or `export PENTEST_CLI_CONFIG=/path/to/mcp.json`
```

```markdown
# Standalone_Build (local / terminal MCP servers)

`Standalone_Build/` is the **local-first** (non-Podman) version of the MCP servers in this repo.

- The original Podman servers (at the repo root) are kept intact as read-only references.
- The standalone copies live here and are safe to modify.
- Default transport is **stdio** so Cursor can launch them as **command MCP servers**.

## Quickstart (recommended)

### 1) Install required host binaries (per tool)

You must install the underlying CLI tools on your host, or set `*_BIN` env vars to point at them.

**Port scanning (coordinator):**
- `rustscan` (or `RUSTSCAN_BIN=/path/to/rustscan`)
- `nmap` (or `NMAP_BIN=/path/to/nmap`)
- `naabu` (or `NAABU_BIN=/path/to/naabu`)

Other standalone servers in this directory have their own host dependencies (WPScan, theHarvester, Searchsploit, etc.).

### 2) Create a single shared Python venv (recommended) and install all servers

Each server directory here is a standalone Python package with a `pyproject.toml`, but you can (and should) run them all from a **single shared venv** to keep Cursor config simple.

Create the shared venv at `Standalone_Build/.venv` and install all servers into it:

```bash
cd "Standalone_Build"
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ./pentest-mcp-server \
            -e ./portscan-mcp-server \
            -e ./dirscan-mcp-server \
            -e ./pdtm-mcp-server \
            -e ./shodan-mcp-server \
            -e ./searchsploit-mcp-server \
            -e ./searx-mcp-server \
            -e ./theharvester-mcp-server \
            -e ./wpscan-mcp-server \
            -e ./mongo-mcp-server \
            -e ./pentest-cli
```

### 3) Run (recommended: `pentest-cli`)

From inside `Standalone_Build/` (venv active), start the interactive CLI:

```bash
pentest-cli
```

Notes:
- The CLI autoloads all servers from `Standalone_Build/mcp.json` so you can call tools as `server.tool` (for example `portscan.nmap_scan` or `shodan.shodan_search`).
- FastMCP banners/logs are written to `Standalone_Build/logs/*.stderr.log` (so the CLI stays readable).

## Wordlists (local-only)

`Standalone_Build/wordlists/` is intentionally **not synced to GitHub** (it can be ~GBs). See:
- `Standalone_Build/WORDLISTS.md`

## Discovering required flags for underlying tools

Some servers wrap other CLIs (for example `pdtm.pd_run` wraps ProjectDiscovery tools like `nuclei`).
To see required/optional flags for a specific wrapped tool, use that tool’s native help via raw mode:

```text
pentest> call pdtm.pd_run_raw {"tool":"nuclei","args":["-h"],"i_acknowledge_risk":true}
```

## Cursor MCP configuration (stdio command server)

Cursor uses stdio “command” MCP servers. A typical `.cursor/mcp.json` entry looks like:

```json
{
  "mcpServers": {
    "portscan": {
      "command": "python",
      "args": ["-m", "pentest_mcp_server.server"],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

Notes:
- This assumes `pentest-mcp-server` was installed into the Python environment Cursor will use to launch the command.
- If you prefer, you can set `command` to an absolute path to the venv Python (recommended for reliability).



```

### Done: documented today’s changes + added per-tool help guidance into `describe pdtm.pd_run`

- **`describe pdtm.pd_run` now includes**:
  - **Supported tools (allowlist)**
  - **How to discover per-tool CLI flags** (via `pd_run_raw` + `args=["-h"]`)
  - **How to pass those flags** (via the `args` JSON array)

Verified in your `Standalone_Build/.venv` runtime, the `pd_run` description now shows the help/args instructions and examples.

### Docs updated
- **`pdtm-mcp-server/README.md`**: Added a “Discover per-tool flags and pass them into `pd_run`” section.
- **`Standalone_Build/pdtm-mcp-server/README.md`**: Added the same, with `pentest-cli` examples.
- **`Standalone_Build/pentest-cli/README.md`**: Added a ProjectDiscovery (`pdtm`) section showing how to get `-h` and pass `args`.
- **`Standalone_Build/README.md`**: Added a short section pointing to `Standalone_Build/WORDLISTS.md` and the `pd_run_raw -h` pattern for discovering required flags.

After restarting the `pdtm` server in Cursor, you’ll see the updated `describe pdtm.pd_run` text automatically.

---

**User**

I just noticed that when I ran the call pdtm.pd_tool {"tool": "nuclei", "args": ["-h"]} function, it "saved: mongo (mcp_db.results) id=69519c616e0bedf7444d8af1" -- is it possible to exclude any automatic saves to Mongo if the arg is just ["-h"]? No need to save that to mongo...

---

**Cursor**

Plan: I’ll find where `pentest-cli` auto-injects `save={"type":"mongo"}` into tool calls, then add a small guard: if the call looks like a “help” invocation (e.g. `args == ["-h"]` / `["--help"]`) and the user didn’t explicitly provide `save`, we skip the auto-save. Then I’ll verify with a quick dry-run in the CLI codepath.

Quick fix: the auto-save is coming from `pentest-cli`’s `_maybe_inject_save_mongo()` (it blindly injects `save={"type":"mongo"}` whenever a tool supports `save`). I’ll add a guard so if the call is *just* a help request (`args == ["-h"]` / `["--help"]`) and you didn’t set `save`, it won’t inject/save.

```python
from __future__ import annotations

import json
import os
import shlex
import sys
import shutil
import re
import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from .config import McpServerConfig, load_dotenv_file, load_mcp_json, safe_json_loads


def _supports_color() -> bool:
    if os.getenv("NO_COLOR") is not None:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _c(text: str, code: str) -> str:
    if not _supports_color():
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def _bold(text: str) -> str:
    return _c(text, "1")


def _dim(text: str) -> str:
    return _c(text, "2")


def _cyan(text: str) -> str:
    return _c(text, "36")


def _green(text: str) -> str:
    return _c(text, "32")


def _yellow(text: str) -> str:
    return _c(text, "33")


def _magenta(text: str) -> str:
    return _c(text, "35")


def _inverse(text: str) -> str:
    return _c(text, "7")


def _color_for_server(server: str) -> str:
    """
    Deterministic ANSI color code for a given server name (cycles a small palette).
    Only used when stdout supports color.
    """
    palette = ["36", "35", "34", "32"]  # cyan, magenta, blue, green
    s = (server or "").strip().lower()
    # Stable hash (avoid Python's randomized hash()).
    h = 0
    for ch in s:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    return palette[h % len(palette)]


def _hr(char: str = "─") -> str:
    """
    Dim horizontal rule sized to terminal width (best-effort).
    """
    try:
        cols = shutil.get_terminal_size(fallback=(80, 20)).columns
    except Exception:
        cols = 80
    cols = max(20, min(int(cols), 200))
    return _dim(char * cols)


def _dump(obj: Any) -> str:
    if hasattr(obj, "model_dump"):
        return json.dumps(obj.model_dump(), indent=2, default=str)
    if hasattr(obj, "dict"):
        return json.dumps(obj.dict(), indent=2, default=str)  # type: ignore[attr-defined]
    return json.dumps(obj, indent=2, default=str)


def _schema_type(schema: Any) -> str:
    """
    Best-effort human type string from a JSON Schema fragment.
    """
    if not isinstance(schema, dict):
        return "unknown"
    t = schema.get("type")
    if isinstance(t, str):
        return t
    if isinstance(t, list):
        return " | ".join(str(x) for x in t)
    if "anyOf" in schema and isinstance(schema["anyOf"], list):
        parts: list[str] = []
        for s in schema["anyOf"]:
            parts.append(_schema_type(s))
        # de-dupe while preserving order
        seen: set[str] = set()
        out: list[str] = []
        for p in parts:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return " | ".join(out) if out else "unknown"
    if "oneOf" in schema and isinstance(schema["oneOf"], list):
        parts = [_schema_type(s) for s in schema["oneOf"]]
        return " | ".join(parts) if parts else "unknown"
    return "object" if "properties" in schema else "unknown"


def _format_describe(tool: Any) -> str:
    """
    Render a tool in a human-friendly format (instead of raw JSON schema).
    Expects an MCP Tool model (mcp.types.Tool).
    """
    name = getattr(tool, "name", "") or ""
    desc = (getattr(tool, "description", "") or "").strip()
    input_schema = getattr(tool, "inputSchema", None)
    output_schema = getattr(tool, "outputSchema", None)

    lines: list[str] = []
    lines.append(_bold(_cyan(f"Tool: {name}")))
    if desc:
        lines.append("")
        lines.append(_bold(_magenta("What it does:")))
        lines.append(f"  {desc}")

    # Inputs
    props: dict[str, Any] = {}
    required: set[str] = set()
    if isinstance(input_schema, dict):
        if isinstance(input_schema.get("properties"), dict):
            props = dict(input_schema["properties"])
        req = input_schema.get("required")
        if isinstance(req, list):
            required = {str(x) for x in req}

    lines.append("")
    lines.append(_bold(_magenta("Inputs:")))
    if not props:
        lines.append(_dim("  (none)"))
    else:
        for k in sorted(props.keys()):
            s = props.get(k)
            t = _schema_type(s)
            nullable = "null" in {p.strip() for p in t.split("|")}
            default = s.get("default") if isinstance(s, dict) else None
            # FastMCP sometimes marks fields as "required" even when a default exists.
            # For UX, treat "has default" as optional-with-default.
            is_req = (k in required) and (default is None)
            suffix_parts: list[str] = []
            if is_req:
                suffix_parts.append(_green("required"))
                if nullable:
                    suffix_parts.append(_dim("nullable"))
            else:
                suffix_parts.append(_yellow("optional"))
            if default is not None:
                suffix_parts.append(f"default={default!r}")
            suffix = ", ".join(suffix_parts)
            lines.append(f"  - {_bold(k)}: {_cyan(t)} ({suffix})")

    # Output
    lines.append("")
    lines.append(_bold(_magenta("Output:")))
    if isinstance(output_schema, dict):
        lines.append(f"  schema_type: {_cyan(_schema_type(output_schema))}")
    else:
        lines.append(f"  schema_type: {_cyan('unknown')}")

    # Example call stub
    example_obj: dict[str, Any] = {}
    for k in sorted(props.keys()):
        s = props.get(k)
        default = s.get("default") if isinstance(s, dict) else None
        t = _schema_type(s)
        nullable = "null" in {p.strip() for p in t.split("|")}

        # Only include "required-like" keys in the example. If FastMCP marked it required
        # but the schema provides a default, users can omit it.
        if k in required and default is None:
            # Prefer a default if present (even though required-set said required).
            if default is not None:
                example_obj[k] = default
                continue

            # Put simple placeholders for required fields
            schema = props.get(k)
            if k == "targets":
                example_obj[k] = ["127.0.0.1"]
            elif k == "url":
                example_obj[k] = "https://example.com"
            elif k == "domain":
                example_obj[k] = "example.com"
            elif k == "ports":
                # Common for scanners that accept N-M.
                example_obj[k] = "1-1024" if not nullable else "1-1024"
            elif t == "boolean":
                example_obj[k] = True
            elif nullable:
                # If the schema says it's required but allows null, use null as the safest default.
                example_obj[k] = None
            elif t in {"integer", "number"}:
                # Use a non-zero default-ish value for common scanner knobs.
                example_obj[k] = 1
            elif t.startswith("array"):
                example_obj[k] = []
            else:
                example_obj[k] = ""

    lines.append("")
    lines.append(_bold(_magenta("How to call:")))
    lines.append(_cyan(f"  call {name} {json.dumps(example_obj, separators=(',', ':'))}"))
    lines.append("")
    lines.append(_bold(_magenta("Notes:")))
    lines.append("  - Some servers mark many fields as 'required' even when they allow null; prefer null for nullable inputs unless you need them.")
    lines.append("")
    lines.append(_bold(_magenta("Raw schema (if you need it):")))
    lines.append(_cyan(f"  describe-json {name}"))
    return "\n".join(lines)


def _format_describe_with_name(tool: Any, *, display_name: str) -> str:
    """
    Same as _format_describe, but override the tool name shown to users (e.g. server.tool).
    """
    # Lightweight approach: clone the object surface by monkeying a few attrs
    # without depending on the exact mcp.types.Tool class.
    class _Wrap:
        def __init__(self, inner: Any, name: str):
            self._inner = inner
            self.name = name

        def __getattr__(self, item: str) -> Any:
            return getattr(self._inner, item)

    return _format_describe(_Wrap(tool, display_name))


def _read_json_arg(token: str) -> dict[str, Any]:
    t = (token or "").strip()
    if not t:
        return {}
    if t.startswith("@"):
        p = Path(t[1:]).expanduser()
        data = safe_json_loads(p.read_text(encoding="utf-8"))
    else:
        data = safe_json_loads(t)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("tool arguments must be a JSON object")
    return data


@dataclass
class ActiveConnection:
    name: str
    cfg: McpServerConfig
    session: ClientSession
    close_fn: Any
    tools_by_name: dict[str, Any]


class PentestCliRepl:
    def __init__(
        self,
        *,
        config_path: str,
        auto_connect: str | None = None,
        default_save_mongo: bool = True,
        autoload_all: bool = True,
    ):
        self.config_path = config_path
        self.servers: dict[str, McpServerConfig] = load_mcp_json(config_path)
        self.conn: ActiveConnection | None = None
        self.conns: dict[str, ActiveConnection] = {}
        self.auto_connect = (auto_connect or "").strip() or None
        self.default_save_mongo = bool(default_save_mongo)
        self.autoload_all = bool(autoload_all)
        self._history_path = os.path.expanduser(os.getenv("PENTEST_CLI_HISTORY", "~/.pentest_cli_history"))
        self._history_ready = False
        self.mongo_db_default = (os.getenv("MONGO_DB", "") or "mcp_db").strip() or "mcp_db"
        self.mongo_collection_default = (os.getenv("MONGO_COLLECTION", "") or "results").strip() or "results"

    def _dotenv_init(self) -> None:
        """
        Load Standalone_Build/.env (if present) so CLI commands (notably Mongo queries)
        see the same configuration as the MCP servers started via run-mcp-stdio.sh.
        """
        if os.getenv("PENTEST_CLI_NO_DOTENV") is not None:
            return
        try:
            # Prefer a .env next to the config file (Standalone_Build/.env)
            base = Path(self.config_path).resolve().parent
            load_dotenv_file(str(base / ".env"), override=False)
        except Exception:
            return

    def _history_init(self) -> None:
        """
        Enable readline history so arrow keys can recall commands.
        On macOS this is typically backed by libedit; importing readline is enough
        for up/down history in most terminals.
        """
        if self._history_ready:
            return
        try:
            import readline  # noqa: F401

            # Best-effort load existing history
            try:
                if os.path.exists(self._history_path):
                    readline.read_history_file(self._history_path)
            except Exception:
                pass
            try:
                readline.set_history_length(5000)
            except Exception:
                pass
            self._history_ready = True
        except Exception:
            # If readline isn't available, we silently proceed (no history).
            self._history_ready = False

    def _history_save(self) -> None:
        if not self._history_ready:
            return
        try:
            import readline

            readline.write_history_file(self._history_path)
        except Exception:
            pass

    async def _input(self, prompt: str) -> str:
        return await anyio.to_thread.run_sync(input, prompt)

    def _print(self, s: str = "") -> None:
        print(s, flush=True)

    def _help(self) -> None:
        self._print(
            "\n".join(
                [
                    "Commands:",
                    "  help                              Show this help",
                    "  reload                            Reload mcp.json",
                    "  servers                           List configured servers",
                    "  connect <server>                  Start and connect to a server (stdio)",
                    "  disconnect                        Disconnect current server",
                    "  status                            Show current connection",
                    "  tools [filter]                    List tools across all servers (qualified as server.tool)",
                    "  describe <server.tool>            Show a human-friendly description + how to call it",
                    "  describe-json <server.tool>       Show the raw MCP JSON schema for a tool",
                    "  call <server.tool> <json|@file>   Call a tool (servers are autoloaded by default)",
                    "  call-json <server.tool> <json|@file> Call a tool and print the full MCP JSON response",
                    "  mongo-use <db> <collection>       Set default Mongo db/collection for queries",
                    "  mongo-find-one <json|@file>       pymongo find_one(filter) on default db/collection",
                    "  mongo-find <json|@file> [limit=N] pymongo find(filter).limit(N) on default db/collection",
                    "  quit | exit                       Exit",
                    "",
                    f"Config: {self.config_path}",
                    _dim("Tip: this CLI prefers qualified tool names like: portscan.naabu_scan  or  shodan.shodan_search"),
                ]
            )
        )

    def _require_conn(self) -> ActiveConnection:
        if not self.conn:
            raise RuntimeError("not connected (use: connect <server>)")
        return self.conn

    def _split_qualified_tool(self, name: str) -> tuple[str | None, str]:
        """
        Parse "server.tool" into ("server", "tool"). If no dot, returns (None, name).
        """
        s = (name or "").strip()
        if "." not in s:
            return None, s
        server, tool = s.split(".", 1)
        server = server.strip()
        tool = tool.strip()
        if not server or not tool:
            return None, s
        return server, tool

    async def _open_connection(self, server_name: str) -> ActiveConnection:
        name = (server_name or "").strip()
        if not name:
            raise ValueError("server name is required")
        cfg = self.servers.get(name)
        if not cfg:
            raise ValueError(f"unknown server: {name}")

        # Make config portable: allow relative command paths in mcp.json
        # and resolve them relative to the config file location.
        cmd = cfg.command
        try:
            if cmd and (not os.path.isabs(cmd)) and (cmd.startswith(".") or ("/" in cmd)):
                base = Path(self.config_path).resolve().parent
                cmd = str((base / cmd).resolve())
        except Exception:
            cmd = cfg.command

        # Merge env: base process env + config env (config overrides).
        env = os.environ.copy()
        env.update(cfg.env)

        params = StdioServerParameters(command=cmd, args=cfg.args, env=env)
        cm = stdio_client(params)
        read_stream, write_stream = await cm.__aenter__()  # type: ignore[misc]

        sess_cm = ClientSession(read_stream, write_stream)
        session = await sess_cm.__aenter__()  # type: ignore[misc]
        try:
            await session.initialize()
        except Exception:
            await sess_cm.__aexit__(None, None, None)  # type: ignore[misc]
            await cm.__aexit__(None, None, None)  # type: ignore[misc]
            raise

        # Cache tools (used to know whether a tool accepts `save`)
        tools_by_name: dict[str, Any] = {}
        try:
            tool_list = await session.list_tools()
            for t in (tool_list.tools or []):
                n = getattr(t, "name", None)
                if isinstance(n, str) and n:
                    tools_by_name[n] = t
        except Exception:
            tools_by_name = {}

        async def _close() -> None:
            try:
                await sess_cm.__aexit__(None, None, None)  # type: ignore[misc]
            finally:
                await cm.__aexit__(None, None, None)  # type: ignore[misc]

        return ActiveConnection(name=name, cfg=cfg, session=session, close_fn=_close, tools_by_name=tools_by_name)

    @contextlib.asynccontextmanager
    async def _temp_connection(self, server_name: str):
        """
        Open a one-off connection to a server for a single command, then close it.
        """
        conn = await self._open_connection(server_name)
        try:
            yield conn
        finally:
            try:
                await conn.close_fn()
            except Exception:
                pass

    async def cmd_reload(self) -> None:
        self.servers = load_mcp_json(self.config_path)
        self._print(f"Reloaded {len(self.servers)} servers from {self.config_path}")

    async def cmd_servers(self) -> None:
        if not self.servers:
            self._print("No servers found in config.")
            return
        self._print("Servers:")
        for k in sorted(self.servers):
            cfg = self.servers[k]
            self._print(f"  - {k}: {cfg.command} {' '.join(cfg.args)}")

    async def cmd_status(self) -> None:
        if not self.conn:
            self._print("Not connected.")
            return
        self._print(f"Connected: {self.conn.name}")
        self._print(f"Command:   {self.conn.cfg.command} {' '.join(self.conn.cfg.args)}")

    async def cmd_disconnect(self) -> None:
        if not self.conn:
            return
        try:
            try:
                await self.conn.close_fn()
            except BaseException:
                # Closing stdio transports can raise cancellation-related exceptions; ignore on shutdown.
                pass
        finally:
            self.conn = None
        self._print("Disconnected.")

    async def cmd_disconnect_all(self) -> None:
        """
        Disconnect all autoloaded servers (and the current connection, if any).
        """
        # Close current connection if it's also in the pool.
        if self.conn:
            try:
                await self.conn.close_fn()
            except BaseException:
                pass
            self.conn = None

        for name in list(self.conns.keys()):
            c = self.conns.pop(name, None)
            if not c:
                continue
            try:
                await c.close_fn()
            except BaseException:
                pass

    async def cmd_autoload_all(self) -> None:
        """
        Start and connect to all configured servers up-front for fast, global tool access.
        """
        loaded: list[str] = []
        failed: dict[str, str] = {}
        for name in sorted(self.servers.keys()):
            if name in self.conns:
                loaded.append(name)
                continue
            try:
                self.conns[name] = await self._open_connection(name)
                loaded.append(name)
            except Exception as e:
                failed[name] = f"{type(e).__name__}: {e}"
        self._print(_dim(f"Autoloaded servers ({len(loaded)}/{len(self.servers)}): {', '.join(loaded) if loaded else '(none)'}"))
        if failed:
            self._print(_bold(_yellow("Some servers failed to load:")))
            for k in sorted(failed.keys()):
                self._print(f"  - {k}: {failed[k]}")

    def _mongo_client(self):
        """
        Create a MongoClient from env MONGO_URI (loaded via .env when available).
        """
        uri = (os.getenv("MONGO_URI", "") or "").strip()
        if not uri:
            raise RuntimeError("MONGO_URI is not set (set it in Standalone_Build/.env)")
        try:
            from pymongo import MongoClient

            return MongoClient(uri, serverSelectionTimeoutMS=3000)
        except Exception as e:
            raise RuntimeError(f"failed to create MongoClient: {e}") from e

    def _jsonable(self, obj: Any) -> Any:
        """
        Convert pymongo/bson types (ObjectId, datetime, etc.) into JSON-friendly values.
        """
        try:
            from bson import ObjectId  # type: ignore
        except Exception:
            ObjectId = None  # type: ignore

        if ObjectId is not None and isinstance(obj, ObjectId):  # type: ignore[arg-type]
            return str(obj)
        if isinstance(obj, dict):
            return {k: self._jsonable(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._jsonable(v) for v in obj]
        return obj

    async def cmd_mongo_use(self, db: str, collection: str) -> None:
        d = (db or "").strip()
        c = (collection or "").strip()
        if not d or not c:
            raise ValueError("usage: mongo-use <db> <collection>")
        self.mongo_db_default = d
        self.mongo_collection_default = c
        self._print(f"Mongo default: {self.mongo_db_default}.{self.mongo_collection_default}")

    async def cmd_mongo_find_one(self, raw_filter: str) -> None:
        filt = _read_json_arg(raw_filter)
        client = self._mongo_client()
        doc = client[self.mongo_db_default][self.mongo_collection_default].find_one(filt)
        if doc is None:
            self._print("(no match)")
            return
        self._print(json.dumps(self._jsonable(doc), indent=2, default=str))

    async def cmd_mongo_find(self, raw_filter: str, *, limit: int = 20) -> None:
        filt = _read_json_arg(raw_filter)
        try:
            limit = int(limit)
        except Exception:
            limit = 20
        limit = max(1, min(limit, 500))
        client = self._mongo_client()
        cur = client[self.mongo_db_default][self.mongo_collection_default].find(filt).limit(limit)
        docs = list(cur)
        if not docs:
            self._print("(no matches)")
            return
        self._print(json.dumps([self._jsonable(d) for d in docs], indent=2, default=str))

    async def cmd_connect(self, server_name: str) -> None:
        # Disconnect existing connection first.
        await self.cmd_disconnect()
        name = (server_name or "").strip()
        if not name:
            raise ValueError("usage: connect <server>")
        self.conn = await self._open_connection(name)
        self._print(f"Connected to {name}.")

    def _maybe_inject_save_mongo(self, conn: ActiveConnection, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """
        If enabled, inject save={"type":"mongo"} for tools that accept a `save` parameter,
        unless the caller explicitly provided a non-null save value.
        """
        if not self.default_save_mongo:
            return args

        # Avoid polluting Mongo with "help/usage" calls (common when exploring CLI flags).
        # Example: pdtm.pd_run_raw {"tool":"nuclei","args":["-h"],"i_acknowledge_risk":true}
        tool_args = args.get("args")
        if isinstance(tool_args, list) and len(tool_args) == 1:
            a0 = (tool_args[0] or "").strip().lower() if isinstance(tool_args[0], str) else ""
            if a0 in {"-h", "--help"}:
                return args

        tool = conn.tools_by_name.get(tool_name)
        input_schema = getattr(tool, "inputSchema", None) if tool is not None else None
        props = input_schema.get("properties") if isinstance(input_schema, dict) else None
        supports_save = isinstance(props, dict) and ("save" in props)

        if not supports_save:
            return args

        if "save" in args and args.get("save") not in (None, {}):
            # Caller explicitly set a save mode; respect it.
            return args

        out = dict(args)
        out["save"] = {"type": "mongo"}
        return out

    async def cmd_tools(self, filt: str | None = None) -> None:
        q = (filt or "").strip().lower()

        # Prefer the autoloaded pool; fall back to on-demand if autoload is disabled.
        servers_to_scan: list[str]
        if q and q in self.servers:
            servers_to_scan = [q]
        else:
            servers_to_scan = sorted(self.servers.keys())

        hidden_tool_names = {"list_tools", "describe_tool"}
        items: list[tuple[str, Any]] = []
        for s in servers_to_scan:
            pooled = self.conns.get(s)
            if pooled is not None:
                res = await pooled.session.list_tools()
                for t in (res.tools or []):
                    if getattr(t, "name", None) in hidden_tool_names:
                        continue
                    items.append((s, t))
                continue
            async with self._temp_connection(s) as conn:
                res = await conn.session.list_tools()
                for t in (res.tools or []):
                    if getattr(t, "name", None) in hidden_tool_names:
                        continue
                    items.append((s, t))

        # Apply substring filter across qualified name + description.
        if q:
            filtered: list[tuple[str, Any]] = []
            for s, t in items:
                name2 = f"{s}.{getattr(t, 'name', '') or ''}".lower()
                desc2 = (getattr(t, "description", "") or "").lower()
                if q in name2 or q in desc2:
                    filtered.append((s, t))
            items = filtered

        self._print(f"Tools ({len(items)}):")
        for s, t in items:
            desc = (t.description or "").strip().splitlines()[0] if getattr(t, "description", None) else ""
            qualified = f"{s}.{t.name}"
            qualified_colored = _c(qualified, _color_for_server(s))
            self._print(f"  - {qualified_colored}: {desc}")

    async def cmd_describe(self, tool_name: str) -> None:
        raw = (tool_name or "").strip()
        if not raw:
            raise ValueError("usage: describe <tool|server.tool>")
        server, name = self._split_qualified_tool(raw)

        if server:
            pooled = self.conns.get(server)
            if pooled is not None:
                res = await pooled.session.list_tools()
                tool = next((t for t in (res.tools or []) if t.name == name), None)
                if not tool:
                    raise ValueError(f"tool not found: {server}.{name}")
                self._print(_format_describe_with_name(tool, display_name=f"{server}.{name}"))
                return
            async with self._temp_connection(server) as conn:
                res = await conn.session.list_tools()
                tool = next((t for t in (res.tools or []) if t.name == name), None)
                if not tool:
                    raise ValueError(f"tool not found: {server}.{name}")
                self._print(_format_describe_with_name(tool, display_name=f"{server}.{name}"))
                return

        raise ValueError("usage: describe <server>.<tool>")

    async def cmd_describe_json(self, tool_name: str) -> None:
        raw = (tool_name or "").strip()
        if not raw:
            raise ValueError("usage: describe-json <tool|server.tool>")
        server, name = self._split_qualified_tool(raw)

        if server:
            pooled = self.conns.get(server)
            if pooled is not None:
                res = await pooled.session.list_tools()
                tool = next((t for t in (res.tools or []) if t.name == name), None)
                if not tool:
                    raise ValueError(f"tool not found: {server}.{name}")
                self._print(_dump(tool))
                return
            async with self._temp_connection(server) as conn:
                res = await conn.session.list_tools()
                tool = next((t for t in (res.tools or []) if t.name == name), None)
                if not tool:
                    raise ValueError(f"tool not found: {server}.{name}")
                self._print(_dump(tool))
                return

        raise ValueError("usage: describe-json <server>.<tool>")

    async def cmd_call(self, tool_name: str, json_arg: str) -> None:
        raw = (tool_name or "").strip()
        if not raw:
            raise ValueError("usage: call <tool|server.tool> <json|@file>")
        server, name = self._split_qualified_tool(raw)

        if not server:
            raise ValueError("usage: call <server>.<tool> <json|@file>")

        pooled = self.conns.get(server)
        if pooled is not None:
            conn = pooled
            args = _read_json_arg(json_arg)
            args = self._maybe_inject_save_mongo(conn, name, args)
            result = await conn.session.call_tool(name=name, arguments=args)
        else:
            async with self._temp_connection(server) as conn:
                args = _read_json_arg(json_arg)
                args = self._maybe_inject_save_mongo(conn, name, args)
                result = await conn.session.call_tool(name=name, arguments=args)

        # Many of our MCP tools return a structured payload like:
        #   {"ok": false, "error": "...", "details": ...}
        # but do not set MCP-level isError=true. Present these as errors in the CLI.
        sc = getattr(result, "structuredContent", None)
        if isinstance(sc, dict) and sc.get("ok") is False:
            err = str(sc.get("error") or "tool error")
            details = sc.get("details")
            self._print(_bold(_yellow("Tool returned ok=false")))
            self._print(f"  error: {err}")
            if details is not None:
                self._print(f"  details: {json.dumps(details, indent=2, default=str)}")
            # Friendly hint for missing binaries.
            if "not found in PATH" in err:
                missing = err.split(" not found in PATH", 1)[0].strip()
                env_var = f"{missing.upper()}_BIN" if missing else "<TOOL>_BIN"
                self._print("")
                self._print(_bold(_magenta("Fix: install the binary or set an explicit path")))
                if missing:
                    self._print(f"  - Install {missing} so it's available on PATH")
                else:
                    self._print("  - Install the missing tool binary so it's available on PATH")
                self._print(f"  - Or set {env_var} in Standalone_Build/.env to the full executable path")
            return

        # Default UX: print stdout/stderr like a CLI tool would.
        if isinstance(sc, dict) and sc.get("ok") is True:
            payload = sc.get("result")
            meta = sc.get("meta") if isinstance(sc.get("meta"), dict) else None
            if isinstance(payload, dict):
                stdout = payload.get("stdout")
                stderr = payload.get("stderr")
                if isinstance(stdout, str) and stdout.strip():
                    print(stdout, end="" if stdout.endswith("\n") else "\n", flush=True)
                if isinstance(stderr, str) and stderr.strip():
                    self._print(_bold(_yellow("stderr:")))
                    print(stderr, end="" if stderr.endswith("\n") else "\n", flush=True)
                # If we printed anything, stop here.
                if meta and isinstance(meta.get("saved"), dict):
                    saved = meta.get("saved") or {}
                    if isinstance(saved, dict):
                        if saved.get("saved") is True:
                            self._print(_dim(f"saved: mongo ({saved.get('db','')}.{saved.get('collection','')}) id={saved.get('inserted_id','')}"))
                        elif saved:
                            self._print(_dim(f"saved: failed ({saved.get('error','unknown error')})"))
                if (isinstance(stdout, str) and stdout.strip()) or (isinstance(stderr, str) and stderr.strip()):
                    return

        # Fallback: show the full MCP response object
        self._print(_dump(result))

    async def cmd_call_json(self, tool_name: str, json_arg: str) -> None:
        """
        Call a tool, but always print the full MCP response (structuredContent/meta).
        """
        raw = (tool_name or "").strip()
        if not raw:
            raise ValueError("usage: call-json <tool|server.tool> <json|@file>")
        server, name = self._split_qualified_tool(raw)

        if not server:
            raise ValueError("usage: call-json <server>.<tool> <json|@file>")

        pooled = self.conns.get(server)
        if pooled is not None:
            args = _read_json_arg(json_arg)
            args = self._maybe_inject_save_mongo(pooled, name, args)
            result = await pooled.session.call_tool(name=name, arguments=args)
            self._print(_dump(result))
            return

        async with self._temp_connection(server) as conn:
            args = _read_json_arg(json_arg)
            args = self._maybe_inject_save_mongo(conn, name, args)
            result = await conn.session.call_tool(name=name, arguments=args)
            self._print(_dump(result))

    async def run(self) -> int:
        self._dotenv_init()
        self._history_init()
        self._print(_dim("Type 'help' for commands."))
        self._print(_dim(f"Config: {self.config_path} (loaded {len(self.servers)} servers)"))
        if self.autoload_all and self.servers:
            await self.cmd_autoload_all()
        if not self.servers:
            self._print(
                _dim(
                    "No servers loaded. Set --config /path/to/mcp.json "
                    "or export PENTEST_CLI_CONFIG=/path/to/mcp.json."
                )
            )
        if self.auto_connect:
            if self.auto_connect in self.servers:
                try:
                    await self.cmd_connect(self.auto_connect)
                except Exception as e:
                    self._print(f"Auto-connect failed ({self.auto_connect}): {type(e).__name__}: {e}")
            else:
                self._print(f"Auto-connect skipped: unknown server '{self.auto_connect}' (try: servers)")
        while True:
            try:
                # Prompt framing (dim rule above/below) + simple prompt text.
                self._print(_hr())
                line = (await self._input("pentest> ")).strip()
                self._print(_hr())
            except (EOFError, KeyboardInterrupt):
                self._print()
                break

            if not line:
                continue

            # Special-case: `call <tool> <json...>` should not be parsed via shlex because
            # shlex will strip quotes inside JSON, breaking valid JSON like {"k":"v"}.
            # Instead, parse the raw remainder and treat it as a JSON blob or @file.
            m_call = re.match(r"^\s*call\s+(\S+)\s+(.+?)\s*$", line, flags=re.IGNORECASE)
            if m_call:
                tool = m_call.group(1)
                raw_arg = m_call.group(2)
                try:
                    await self.cmd_call(tool, raw_arg)
                except Exception as e:
                    # Provide a more actionable error for common JSON quoting problems.
                    if isinstance(e, json.JSONDecodeError):
                        self._print(
                            "Error: invalid JSON.\n"
                            "  Tip: paste JSON exactly (as you did), or use @file.json.\n"
                            "  If your JSON contains spaces/newlines, wrap it in single quotes:\n"
                            "    call <tool> '{\"k\":\"v\"}'"
                        )
                    else:
                        self._print(f"Error: {type(e).__name__}: {e}")
                continue

            m_call_json = re.match(r"^\s*call-json\s+(\S+)\s+(.+?)\s*$", line, flags=re.IGNORECASE)
            if m_call_json:
                tool = m_call_json.group(1)
                raw_arg = m_call_json.group(2)
                try:
                    await self.cmd_call_json(tool, raw_arg)
                except Exception as e:
                    if isinstance(e, json.JSONDecodeError):
                        self._print(
                            "Error: invalid JSON.\n"
                            "  Tip: use @file.json, or wrap inline JSON in single quotes:\n"
                            "    call-json <tool> '{\"k\":\"v\"}'"
                        )
                    else:
                        self._print(f"Error: {type(e).__name__}: {e}")
                continue

            # Mongo query commands accept raw JSON after the command (same reasoning as `call`).
            m_mf1 = re.match(r"^\s*mongo-find-one\s+(.+?)\s*$", line, flags=re.IGNORECASE)
            if m_mf1:
                try:
                    await self.cmd_mongo_find_one(m_mf1.group(1))
                except Exception as e:
                    self._print(f"Error: {type(e).__name__}: {e}")
                continue

            m_mf = re.match(r"^\s*mongo-find\s+(.+?)\s*$", line, flags=re.IGNORECASE)
            if m_mf:
                raw = m_mf.group(1).strip()
                # Allow trailing " limit=N" convenience.
                limit = 20
                m_lim = re.search(r"\s+limit=(\d+)\s*$", raw)
                if m_lim:
                    try:
                        limit = int(m_lim.group(1))
                    except Exception:
                        limit = 20
                    raw = re.sub(r"\s+limit=\d+\s*$", "", raw).strip()
                try:
                    await self.cmd_mongo_find(raw, limit=limit)
                except Exception as e:
                    self._print(f"Error: {type(e).__name__}: {e}")
                continue

            try:
                parts = shlex.split(line)
            except ValueError as e:
                self._print(f"Parse error: {e}")
                continue

            cmd = parts[0].lower()
            args = parts[1:]

            try:
                if cmd in {"quit", "exit"}:
                    break
                if cmd in {"help", "?"}:
                    self._help()
                elif cmd == "reload":
                    await self.cmd_reload()
                elif cmd == "servers":
                    await self.cmd_servers()
                elif cmd == "connect":
                    await self.cmd_connect(args[0] if args else "")
                elif cmd == "disconnect":
                    await self.cmd_disconnect()
                elif cmd == "status":
                    await self.cmd_status()
                elif cmd == "tools":
                    await self.cmd_tools(args[0] if args else None)
                elif cmd == "describe":
                    await self.cmd_describe(args[0] if args else "")
                elif cmd in {"describe-json", "describe_json"}:
                    await self.cmd_describe_json(args[0] if args else "")
                elif cmd == "mongo-use":
                    if len(args) < 2:
                        raise ValueError("usage: mongo-use <db> <collection>")
                    await self.cmd_mongo_use(args[0], args[1])
                elif cmd == "call":
                    if len(args) < 2:
                        raise ValueError("usage: call <tool> <json|@file>")
                    await self.cmd_call(args[0], args[1])
                elif cmd in {"call-json", "call_json"}:
                    if len(args) < 2:
                        raise ValueError("usage: call-json <tool> <json|@file>")
                    await self.cmd_call_json(args[0], args[1])
                else:
                    self._print(f"Unknown command: {cmd} (type 'help')")
            # NOTE: mcp.types.ErrorData is a data model, not an Exception.
            # MCP client failures surface as regular Exceptions (e.g., McpError).
            except Exception as e:
                if isinstance(e, json.JSONDecodeError):
                    self._print(
                        "Error: invalid JSON.\n"
                        "  Tip: use @file.json, or wrap inline JSON in single quotes:\n"
                        "    call <tool> '{\"k\":\"v\"}'"
                    )
                    continue
                self._print(f"Error: {type(e).__name__}: {e}")

        await self.cmd_disconnect()
        await self.cmd_disconnect_all()
        self._history_save()
        return 0



```

Yes — I updated `pentest-cli` so **help calls won’t auto-save to Mongo**.

### What changed
In `Standalone_Build/pentest-cli/src/pentest_cli/repl.py`, the CLI now **skips the automatic `save={"type":"mongo"}` injection** when:

- the request has an `args` field and
- it is **exactly** `["-h"]` or `["--help"]`, and
- you didn’t explicitly set `save`

So this will no longer generate a `saved: mongo ...` record:

```text
pentest> call pdtm.pd_run_raw {"tool":"nuclei","args":["-h"],"i_acknowledge_risk":true}
```

### What you need to do
Restart `pentest-cli` (and if needed, reinstall editable package in the shared venv) so it picks up the change.

```plaintext
pentest> call pdtm.pd_run_raw {"tool":"nuclei","args":["-h"],"i_acknowledge_risk":true}
```

---

**User**

It looks like I can just run "call pdtm.pd_run {"tool":"nuclei","args":["-h"]}" and get the same output - could you please change the "describe pdtm.pd_run" to use pdtm.pd_run vs. pdtm.pd_run_raw?

---

**Cursor**

Got it — since `pd_run` already returns Nuclei’s help output fine with `args:["-h"]`, I’ll update the **embedded `describe pdtm.pd_run` guidance** to recommend `pd_run` (safe mode) for help discovery. I’ll also sync the related READMEs so they don’t contradict the updated recommendation.

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help:\n\n"
            + '- `pd_run` with `args=["-h"]`\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"] }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: If you need to use flags blocked by safe mode, use `pd_run_raw` (requires `i_acknowledge_risk=true`).\n"
            + "You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help:\n\n"
            + '- `pd_run` with `args=["-h"]`\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"] }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: If you need to use flags blocked by safe mode, use `pd_run_raw` (requires `i_acknowledge_risk=true`).\n"
            + "You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```markdown
## pdtm-mcp-server

An MCP server that exposes **multiple ProjectDiscovery tools** (installed via **PDTM**) behind a single FastMCP server.

- PDTM repo: [projectdiscovery/pdtm](https://github.com/projectdiscovery/pdtm)
- ProjectDiscovery OSS docs: [ProjectDiscovery Open Source Tools](https://docs.projectdiscovery.io/opensource)

This server listens on **port 4599** inside the container and is intended to be run under **Podman** (works with Docker too).

### Tools exposed

- **`pd_run`**: Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).
- **`pd_run_raw`**: Run a supported ProjectDiscovery tool with arbitrary args (requires `i_acknowledge_risk=true`).
- **`pd_smart`**: Accept a vague intent (e.g. “find subdomains for example.com”) and choose a tool + flags.

### Discover per-tool flags (required/optional) and pass them into `pd_run`

`pd_run` is a generic wrapper: the "required flags" are whatever the underlying ProjectDiscovery tool requires.

- To see a tool’s native help/usage (flags, defaults, required inputs), run `-h` via raw mode:

```json
{
  "tool": "nuclei",
  "args": ["-h"]
}
```

- To pass flags/options into a tool, use `args` (a list of CLI tokens). Example:

```json
{
  "tool": "nuclei",
  "args": ["-u", "https://example.com", "-severity", "high"]
}
```

### Cursor (MCP stdio)

Cursor MCP “command” servers communicate over **stdio**. Use one of the following:

- **Podman stdio wrapper**: run `./cursor-stdio.sh` (after building the image).
- **mcp.json env**: ensure `MCP_TRANSPORT=stdio` is set for this server.

### Examples

**Subdomains (explicit):**

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-d", "example.com"]
}
```

**Subdomains (smart):**

```json
{
  "request": "Please find me the subdomains for example.com"
}
```

**Save to a file in `/data/output`:**

```json
{
  "tool": "httpx",
  "args": ["-silent", "-sc", "-title"],
  "stdin_lines": ["https://example.com"],
  "save": { "type": "file", "filename": "httpx-example.json" }
}
```

**Save to MongoDB:**

```json
{
  "request": "crawl https://example.com",
  "save": { "type": "mongo", "mongo_db": "recon", "mongo_collection": "katana_runs" }
}
```

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-all", "-d", "warnermusic.com"],
  "timeout_seconds": 600,
  "save": { "type": "file" }
}

# List
{ "prefix": "warnermusic.com-2025-12-25", "recursive": true }

# Read/Download
{ "path": "warnermusic.com-2025-12-25/subfinder.json", "max_bytes": 2000000, "as_base64": false }
```

### Result persistence

- **Files**: save to `/data/output` (mount a Podman volume; recommended)
- **MongoDB**: save to a database/collection (configure via env)

### Podman run (HTTP MCP on port 4599)

Build:

```bash
podman build -t pdtm-mcp-server -f Containerfile .
```

Run (expose port 4599 and persist outputs):

```bash
podman volume create pdtm_data
podman run --rm -p 4599:4599 -v pdtm_data:/data/output pdtm-mcp-server
```

### File layout in the Podman volume (recommended)

When saving with `{"save": {"type": "file"}}`, the server writes into `OUTPUT_DIR` (default `/data/output`).

- If `save.run_dir` is not provided, the server will auto-create (or reuse) a directory named:
  - `<target>-YYYY-MM-DD` (example: `wmg.com-2025-12-25`)
- If `save.filename` is not provided, the server defaults to:
  - `<tool>.json` (example: `subfinder.json`)
- If a file name already exists, the server will **not overwrite** it; it will append:
  - `-HH_MM_SS` (and a counter if needed)

Example save:

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-d", "wmg.com"],
  "timeout_seconds": 600,
  "save": { "type": "file" }
}
```

### Browsing / downloading saved results (via MCP)

- **`pd_results_list`**: list files/dirs under `/data/output` (Podman volume)
- **`pd_results_read`**: read a file from `/data/output` (text or base64) — this is the supported “download” path
- **`pd_results_export`**: copy a file from `/data/output` into `/data/downloads` (requires a host bind-mount)

To export directly into your host `~/Downloads` folder, bind-mount it to `/data/downloads` when launching the container.

- **Via `cursor-stdio.sh`**:

```bash
PDTM_OUTPUT_VOLUME=pdtm_data PDTM_DOWNLOADS_DIR="$HOME/Downloads" ./cursor-stdio.sh
```

- **Via `mcp.json`** (example on macOS):

```json
"-v",
"/Users/pkincaid/Downloads:/data/downloads"
```

### Note on transports

- **stdio**: for Cursor (set `MCP_TRANSPORT=stdio`)
- **HTTP**: for networked use (set `MCP_TRANSPORT=streamable-http`, default in the Containerfile)

### MongoDB configuration

Set these env vars when running the container:

- `MONGO_URI` (example: `mongodb://mongo:27017`)
- `MONGO_DB` (default: `pdtm_mcp`)

### Notes / references

- PDTM is ProjectDiscovery’s tool manager: [projectdiscovery/pdtm](https://github.com/projectdiscovery/pdtm)
- General docs for ProjectDiscovery OSS tools: [ProjectDiscovery Open Source Tools](https://docs.projectdiscovery.io/opensource)
- Recon workflow inspiration (3rd-party article): `https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a`


## mcp.json

```
{
  "mcpServers": {
    "project_discovery": {
      "command": "podman",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e",
        "MCP_TRANSPORT=stdio",
        "-v",
        "pdtm_data:/data/output",
        "--name",
        "pdtm-mcp-stdio",
        "pdtm-mcp-server"
      ]
    }
  }
}
```
```

```markdown
## pdtm-mcp-server

An MCP server that exposes **multiple ProjectDiscovery tools** (installed via **PDTM**) behind a single FastMCP server.

- PDTM repo: [projectdiscovery/pdtm](https://github.com/projectdiscovery/pdtm)
- ProjectDiscovery OSS docs: [ProjectDiscovery Open Source Tools](https://docs.projectdiscovery.io/opensource)

In `Standalone_Build`, this server is intended to be launched locally via **stdio** and called from `pentest-cli` as `pdtm.<tool>`.

### Tools exposed

- **`pd_run`**: Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).
- **`pd_run_raw`**: Run a supported ProjectDiscovery tool with arbitrary args (requires `i_acknowledge_risk=true`).
- **`pd_smart`**: Accept a vague intent (e.g. “find subdomains for example.com”) and choose a tool + flags.

### Cursor (MCP stdio)

Cursor MCP “command” servers communicate over **stdio**. In the standalone build, `Standalone_Build/mcp.json` already sets `MCP_TRANSPORT=stdio` and launches this server via `Standalone_Build/run-mcp-stdio.sh`.

### Run (stdio)

From `Standalone_Build/`:

```bash
./run-mcp-stdio.sh pdtm_mcp_server.server
```

### Call from `pentest-cli`

```text
pentest> call pdtm.pd_supported_tools {}
pentest> call pdtm.pd_smart {"request":"find subdomains for example.com","domain":"example.com"}
```

### Discover per-tool flags (required/optional) and pass them into `pd_run`

`pd_run` is a generic wrapper: the "required flags" are whatever the underlying ProjectDiscovery tool requires.

From `pentest-cli`, the easiest way to see a tool’s native help/usage (flags, defaults, required inputs) is:

```text
pentest> call pdtm.pd_run {"tool":"nuclei","args":["-h"]}
```

Then pass the tool flags via `args`:

```text
pentest> call pdtm.pd_run {"tool":"nuclei","args":["-u","https://example.com","-severity","high"]}
```

### Examples

**Subdomains (explicit):**

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-d", "example.com"]
}
```

**Subdomains (smart):**

```json
{
  "request": "Please find me the subdomains for example.com"
}
```

**Save to a file in `/data/output`:**

```json
{
  "tool": "httpx",
  "args": ["-silent", "-sc", "-title"],
  "stdin_lines": ["https://example.com"],
  "save": { "type": "file", "filename": "httpx-example.json" }
}
```

**Save to MongoDB:**

```json
{
  "request": "crawl https://example.com",
  "save": { "type": "mongo", "mongo_db": "recon", "mongo_collection": "katana_runs" }
}
```

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-all", "-d", "warnermusic.com"],
  "timeout_seconds": 600,
  "save": { "type": "file" }
}

# List
{ "prefix": "warnermusic.com-2025-12-25", "recursive": true }

# Read/Download
{ "path": "warnermusic.com-2025-12-25/subfinder.json", "max_bytes": 2000000, "as_base64": false }
```

### Result persistence

- **Files**: save to `OUTPUT_DIR` (configure via env; in `Standalone_Build` this is typically set via `Standalone_Build/.env`)
- **MongoDB**: save to a database/collection (configure via env / `Standalone_Build/.env`)

### Podman run (reference)

Build:

```bash
podman build -t pdtm-mcp-server -f Containerfile .
```

Run (expose port 4599 and persist outputs):

```bash
podman volume create pdtm_data
podman run --rm -p 4599:4599 -v pdtm_data:/data/output pdtm-mcp-server
```

### File layout in `OUTPUT_DIR` (recommended)

When saving with `{"save": {"type": "file"}}`, the server writes into `OUTPUT_DIR`.

- If `save.run_dir` is not provided, the server will auto-create (or reuse) a directory named:
  - `<target>-YYYY-MM-DD` (example: `wmg.com-2025-12-25`)
- If `save.filename` is not provided, the server defaults to:
  - `<tool>.json` (example: `subfinder.json`)
- If a file name already exists, the server will **not overwrite** it; it will append:
  - `-HH_MM_SS` (and a counter if needed)

Example save:

```json
{
  "tool": "subfinder",
  "args": ["-silent", "-d", "wmg.com"],
  "timeout_seconds": 600,
  "save": { "type": "file" }
}
```

### Browsing / downloading saved results (via MCP)

- **`pd_results_list`**: list files/dirs under `OUTPUT_DIR`
- **`pd_results_read`**: read a file from `OUTPUT_DIR` (text or base64)
- **`pd_results_export`**: copy a file from `OUTPUT_DIR` into `DOWNLOAD_DIR` (requires a host bind-mount when containerized)

To export directly into your host `~/Downloads` folder, bind-mount it to `/data/downloads` when launching the container.

- **Via `cursor-stdio.sh`**:

```bash
PDTM_OUTPUT_VOLUME=pdtm_data PDTM_DOWNLOADS_DIR="$HOME/Downloads" ./cursor-stdio.sh
```

- **Via `mcp.json`** (example on macOS):

```json
"-v",
"/Users/pkincaid/Downloads:/data/downloads"
```

### Note on transports

- **stdio**: for Cursor (set `MCP_TRANSPORT=stdio`)
- **HTTP**: for networked use (set `MCP_TRANSPORT=streamable-http`, default in the Containerfile)

### MongoDB configuration

Set these env vars when running the container:

- `MONGO_URI` (example: `mongodb://mongo:27017`)
- `MONGO_DB` (default: `pdtm_mcp`)

### Notes / references

- PDTM is ProjectDiscovery’s tool manager: [projectdiscovery/pdtm](https://github.com/projectdiscovery/pdtm)
- General docs for ProjectDiscovery OSS tools: [ProjectDiscovery Open Source Tools](https://docs.projectdiscovery.io/opensource)
- Recon workflow inspiration (3rd-party article): `https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a`


## mcp.json

```
{
  "mcpServers": {
    "project_discovery": {
      "command": "podman",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e",
        "MCP_TRANSPORT=stdio",
        "-v",
        "pdtm_data:/data/output",
        "--name",
        "pdtm-mcp-stdio",
        "pdtm-mcp-server"
      ]
    }
  }
}
```
```

```markdown
# pentest-cli

Interactive terminal CLI for calling MCP tools over **stdio** using a local `mcp.json`.

## Install (shared venv)

From `Standalone_Build/`:

```bash
source .venv/bin/activate
pip install -e ./pentest-cli
```

## Run

```bash
pentest-cli
```

## Startup behavior

- By default, `pentest-cli` **autoloads (starts) all MCP servers** from `Standalone_Build/mcp.json` so all tools are immediately available.
- To disable autoloading (start servers only when you explicitly `connect`), run: `pentest-cli --no-autoload-all`
- Server stderr logs (FastMCP banners, logs, etc.) are redirected to: `Standalone_Build/logs/*.stderr.log`

## Commands

- `servers` — list configured servers from `Standalone_Build/mcp.json`
- `connect <server>` — connect to a server (optional; autoload already connects everything by default)
- `status` — show current connection (mostly useful when using `connect`)
- `tools [filter]` — list tools across all servers (shows `server.tool` and hides `list_tools`/`describe_tool`)
- `describe <server.tool>` — human-friendly help for a tool (inputs + example call)
- `describe-json <server.tool>` — raw tool schema (MCP JSON schema)
- `call <server.tool> <json|@file>` — call a tool (prints stdout/stderr by default)
- `call-json <server.tool> <json|@file>` — call a tool and print full MCP JSON response
- `mongo-use <db> <collection>` — set default db/collection for CLI Mongo queries
- `mongo-find-one <json|@file>` — run `find_one(filter)` against default db/collection
- `mongo-find <json|@file> [limit=N]` — run `find(filter).limit(N)` against default db/collection
- `quit` / `exit` — leave the shell

## Examples (portscan coordinator)

List tools:

```text
pentest> tools
pentest> tools scan
```

Describe a tool:

```text
pentest> describe portscan.nmap_scan
pentest> describe-json portscan.nmap_scan
```

Nmap scan (ports 1-1024):

```text
pentest> call portscan.nmap_scan {"targets":["192.168.1.1"],"args":["-p","1-1024","-sT"],"force_unprivileged":true}
```

RustScan scan (ports 1-1024):

```text
pentest> call portscan.rustscan_scan {"targets":["192.168.1.1"],"ports":"1-1024"}
```

All-in-one port scanning (naabu + rustscan + nmap):

```text
pentest> call portscan.portscan_all {"targets":["192.168.1.1"],"nmap_style_args":["-p","1-1024","-sT"]}
```

Notes:
- By default, `pentest-cli` injects `save={"type":"mongo"}` for tools that support saving (unless you run with `--no-save-mongo`).
- Ensure `MONGO_URI` is set and MongoDB is running, or you’ll see `saved: failed (...)`.

## Examples (other servers)

All tools are called the same way: `server.tool`.

### Shodan

```text
pentest> tools shodan
pentest> describe shodan.shodan_search
pentest> call shodan.shodan_search {"query":"org:\"Example Corp\"","max_results":5}
```

### Searchsploit

```text
pentest> call searchsploit.searchsploit_search {"terms":["wordpress","plugin"],"case_insensitive":true}
```

### theHarvester

```text
pentest> call theharvester.theharvester_run {"domain":"example.com","sources":"all","limit":200,"start":0}
```

### WPScan

```text
pentest> call wpscan.wpscan_scan {"url":"https://example.com","enumerate":"vp,vt,cb,u","stealthy":true}
```

### SearXNG

```text
pentest> call searx.searx_search {"query":"example.com exposed admin","max_results":10}
```

### ProjectDiscovery tools (via `pdtm`)

`pdtm.pd_run` is a generic wrapper around ProjectDiscovery CLIs (e.g. `nuclei`, `httpx`, `naabu`).
To see what flags a specific tool supports (and what it requires), run its native help:

```text
pentest> call pdtm.pd_run {"tool":"nuclei","args":["-h"]}
```

Then pass the flags you want via `args`:

```text
pentest> call pdtm.pd_run {"tool":"nuclei","args":["-u","https://example.com","-severity","high"]}
```

## MongoDB query examples (CLI-side, via pymongo)

Set default db/collection for queries:

```text
pentest> mongo-use mcp_db results
```

Find one recent run for a tool:

```text
pentest> mongo-find-one {"tool_name":"nmap"}
```

Find many (limit 5):

```text
pentest> mongo-find {"tool_name":"portscan_all"} limit=5
```

## Config and .env

`pentest-cli` uses:
- `Standalone_Build/mcp.json` for server definitions
- `Standalone_Build/.env` (auto-loaded, unless `PENTEST_CLI_NO_DOTENV` is set) for variables like `MONGO_URI`, `MONGO_DB`, `MONGO_COLLECTION`

## Config discovery

By default, `pentest-cli` auto-discovers `Standalone_Build/mcp.json` even when run outside the repo.

To force a specific config:

- `pentest-cli --config "/Users/pkincaid/Documents/bin/joesgarage.ai - AI Projects/MCP_Servers/Standalone_Build/mcp.json"`
- or `export PENTEST_CLI_CONFIG=/path/to/mcp.json`
```

```markdown
# Standalone_Build (local / terminal MCP servers)

`Standalone_Build/` is the **local-first** (non-Podman) version of the MCP servers in this repo.

- The original Podman servers (at the repo root) are kept intact as read-only references.
- The standalone copies live here and are safe to modify.
- Default transport is **stdio** so Cursor can launch them as **command MCP servers**.

## Quickstart (recommended)

### 1) Install required host binaries (per tool)

You must install the underlying CLI tools on your host, or set `*_BIN` env vars to point at them.

**Port scanning (coordinator):**
- `rustscan` (or `RUSTSCAN_BIN=/path/to/rustscan`)
- `nmap` (or `NMAP_BIN=/path/to/nmap`)
- `naabu` (or `NAABU_BIN=/path/to/naabu`)

Other standalone servers in this directory have their own host dependencies (WPScan, theHarvester, Searchsploit, etc.).

### 2) Create a single shared Python venv (recommended) and install all servers

Each server directory here is a standalone Python package with a `pyproject.toml`, but you can (and should) run them all from a **single shared venv** to keep Cursor config simple.

Create the shared venv at `Standalone_Build/.venv` and install all servers into it:

```bash
cd "Standalone_Build"
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ./pentest-mcp-server \
            -e ./portscan-mcp-server \
            -e ./dirscan-mcp-server \
            -e ./pdtm-mcp-server \
            -e ./shodan-mcp-server \
            -e ./searchsploit-mcp-server \
            -e ./searx-mcp-server \
            -e ./theharvester-mcp-server \
            -e ./wpscan-mcp-server \
            -e ./mongo-mcp-server \
            -e ./pentest-cli
```

### 3) Run (recommended: `pentest-cli`)

From inside `Standalone_Build/` (venv active), start the interactive CLI:

```bash
pentest-cli
```

Notes:
- The CLI autoloads all servers from `Standalone_Build/mcp.json` so you can call tools as `server.tool` (for example `portscan.nmap_scan` or `shodan.shodan_search`).
- FastMCP banners/logs are written to `Standalone_Build/logs/*.stderr.log` (so the CLI stays readable).

## Wordlists (local-only)

`Standalone_Build/wordlists/` is intentionally **not synced to GitHub** (it can be ~GBs). See:
- `Standalone_Build/WORDLISTS.md`

## Discovering required flags for underlying tools

Some servers wrap other CLIs (for example `pdtm.pd_run` wraps ProjectDiscovery tools like `nuclei`).
To see required/optional flags for a specific wrapped tool, use that tool’s native help:

```text
pentest> call pdtm.pd_run {"tool":"nuclei","args":["-h"]}
```

## Cursor MCP configuration (stdio command server)

Cursor uses stdio “command” MCP servers. A typical `.cursor/mcp.json` entry looks like:

```json
{
  "mcpServers": {
    "portscan": {
      "command": "python",
      "args": ["-m", "pentest_mcp_server.server"],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

Notes:
- This assumes `pentest-mcp-server` was installed into the Python environment Cursor will use to launch the command.
- If you prefer, you can set `command` to an absolute path to the venv Python (recommended for reliability).



```

Updated — `describe pdtm.pd_run` now recommends using **`pdtm.pd_run`** (not `pd_run_raw`) for help discovery.

Specifically, it now says to run:

```text
{ "tool": "nuclei", "args": ["-h"] }
```

…and keeps a short tip that if you ever hit a **safe-mode blocked flag**, then use `pd_run_raw` (with `i_acknowledge_risk=true`).

I also synced the related READMEs so they match this new guidance.

```plaintext
{ "tool": "nuclei", "args": ["-h"] }
```

---

**User**

I would like an option to be able to set the "i_acknowledge_risk" setting to "true" from within the .env file (perhaps call the variable within .env to be "i_ack_risk_default_true" - so it is more verbose and would be "true" to set all "i_acknowledge_risk" to "true" in the *_raw tools, and if that variable in .env is "false", then the user must specify the "i_acknowledge_risk" in the tool call and any of the *_raw tools use that value.

---

**Cursor**

Plan: I’ll add an env-driven default for `i_acknowledge_risk` so you can flip it globally from `Standalone_Build/.env`. Implementation steps: find every `*_raw` tool that currently hard-defaults `i_acknowledge_risk=False`, change it to `bool | None = None`, then at runtime resolve `None` to `I_ACK_RISK_DEFAULT_TRUE` (or your `i_ack_risk_default_true`) and enforce accordingly. Finally I’ll update `.env-sample` and the relevant tool docs so it’s obvious how to use.

Nice—this is a clean place to solve it: the “must ack” behavior lives inside each server’s `*_raw` tool, and your `.env` is already loaded into the server process via `Standalone_Build/run-mcp-stdio.sh`. Next I’ll add a small env resolver (`i_ack_risk_default_true`) and wire it into every `*_raw` tool (pdtm/portscan/wpscan/dirscan/pentest).

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help:\n\n"
            + '- `pd_run` with `args=["-h"]`\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"] }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: If you need to use flags blocked by safe mode, use `pd_run_raw` (requires `i_acknowledge_risk=true`).\n"
            + "You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help:\n\n"
            + '- `pd_run` with `args=["-h"]`\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"] }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: If you need to use flags blocked by safe mode, use `pd_run_raw` (requires `i_acknowledge_risk=true`).\n"
            + "You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help:\n\n"
            + '- `pd_run` with `args=["-h"]`\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"] }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: If you need to use flags blocked by safe mode, use `pd_run_raw` (requires `i_acknowledge_risk=true`).\n"
            + "You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help:\n\n"
            + '- `pd_run` with `args=["-h"]`\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"] }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: If you need to use flags blocked by safe mode, use `pd_run_raw` (requires `i_acknowledge_risk=true`).\n"
            + "You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```plaintext
# Standalone_Build shared environment for local (non-Podman) MCP servers.
# NOTE: This file may contain secrets. Do not commit.

# Common
LOG_LEVEL="INFO"
PYTHONUNBUFFERED="1"
MCP_TRANSPORT="stdio"

# Raw-mode acknowledgement defaults
# If true-ish, *_raw tools will treat omitted `i_acknowledge_risk` as true.
# If false/empty, you must explicitly pass `i_acknowledge_risk:true` per call.
i_ack_risk_default_true="false"

# Port scanning defaults (pentest/portscan)
NMAP_FORCE_UNPRIVILEGED="1"

# Optional persistence (used by multiple servers when save.type == "mongo")
# Example (local Mongo): MONGO_URI="mongodb://localhost:27017"
MONGO_URI="mongodb://localhost:27017"
MONGO_DB="mcp_db"
MONGO_COLLECTION="results"

# Shodan (required if you use shodan tools)
SHODAN_API_KEY=""

# WPScan (optional API token, depending on your usage)
WPSCAN_API_TOKEN=""

# SearXNG (if you run a local searxng instance)
SEARXNG_URL="http://127.0.0.1:8080"

# theHarvester output (ensure these directories exist)
HARVESTER_OUTPUT_DIR="<PROJECT_ROOT>/output/theharvester"

# PDTM output/download paths (ensure OUTPUT_DIR exists)
OUTPUT_DIR="<PROJECT_ROOT>/output/pdtm"
DOWNLOAD_DIR="$HOME/Downloads"

# Optional explicit binary paths (leave empty to use PATH lookup)
RUSTSCAN_BIN="/opt/homebrew/bin/rustscan"
NMAP_BIN="/opt/homebrew/bin/nmap"
NAABU_BIN="$HOME/.pdtm/go/bin/naabu"

WORDLISTS_ROOT="<PROJECT_ROOT>/wordlists"

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help:\n\n"
            + '- `pd_run` with `args=["-h"]`\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"] }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: If you need to use flags blocked by safe mode, use `pd_run_raw` (requires `i_acknowledge_risk=true`).\n"
            + "You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    elif fn.__name__ == "pd_run_raw":
        # Make the env-based raw acknowledgement discoverable from `describe pdtm.pd_run_raw`.
        doc = (doc or "").rstrip() + (
            "\n\nRaw acknowledgement default\n\n"
            "You may omit `i_acknowledge_risk` if you set env `i_ack_risk_default_true=true` "
            "(or `I_ACK_RISK_DEFAULT_TRUE=true`)."
        )
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
import shutil
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .results_fs import export_result_file, list_results, read_result_file
from .runners import BinaryNotFoundError, run_pd_tool
from .smart import build_smart_plan
from .storage import SaveSpec, save_to_file, save_to_mongo
from .validation import ValidationResult, clamp_int, validate_args, validate_lines, validate_tool_name


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="projectdiscovery-tools")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

# Tools installed via PDTM in Containerfile (allowlist).
_SUPPORTED_TOOLS: set[str] = {"subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "tlsx"}

# In "safe mode" we block a handful of flags that primarily do file IO / config IO.
_BLOCKED_FLAGS_SAFE = {
    "-o",
    "-output",
    "-output-file",
    "-resume",
    "-config",
    "-store-response-dir",
    "-store-response",
    "-pcap",
}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""

    # Enrich select tool docs with dynamic allowlist info so Cursor's `describe server.tool`
    # is self-contained.
    if fn.__name__ == "pd_run":
        supported = sorted(_SUPPORTED_TOOLS)
        allowlist_doc = "\n".join([f"- {t}" for t in supported])
        doc = (
            doc
            + "\n\nSupported tools (allowlist)\n\n"
            + allowlist_doc
            + "\n\nHow to discover per-tool CLI flags (recommended)\n\n"
            + "ProjectDiscovery tools (like `nuclei`, `httpx`, etc.) have their own CLI flags and help output.\n"
            + "To see what a specific tool supports, call its built-in help:\n\n"
            + '- `pd_run` with `args=["-h"]`\n\n'
            + "Example (Nuclei help):\n\n"
            + '{ "tool": "nuclei", "args": ["-h"] }\n\n'
            + "How to pass flags to a tool\n\n"
            + "- Use the `args` field (list of CLI tokens).\n"
            + "- Optionally pass targets via CLI flags (e.g. `-u`, `-l`) or via `stdin_lines`.\n\n"
            + "Example (run Nuclei with flags):\n\n"
            + '{ "tool": "nuclei", "args": ["-u", "https://example.com", "-severity", "high"] }\n\n'
            + "Tip: If you need to use flags blocked by safe mode, use `pd_run_raw` (requires `i_acknowledge_risk=true`).\n"
            + "You can also call `pd_supported_tools()` to retrieve the allowlist programmatically."
        )
        # Ensure FastMCP uses the enriched docstring (it reads __doc__ when wrapping).
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    elif fn.__name__ == "pd_run_raw":
        # Make the env-based raw acknowledgement discoverable from `describe pdtm.pd_run_raw`.
        doc = (doc or "").rstrip() + (
            "\n\nRaw acknowledgement default\n\n"
            "You may omit `i_acknowledge_risk` if you set env `i_ack_risk_default_true=true` "
            "(or `I_ACK_RISK_DEFAULT_TRUE=true`)."
        )
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP's schema generator treats string annotations (from `from __future__ import annotations`)
    # as "unknown" and can incorrectly mark optional params as required. If we can resolve real
    # type hints here, attach them back onto the function before FastMCP wraps it.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "raw flags may enable aggressive scanning and arbitrary file IO"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


def _parse_save_spec(save: dict[str, Any] | None) -> SaveSpec:
    if not save:
        return SaveSpec(type="none")
    t = (save.get("type") or "none").strip().lower()
    if t not in ("none", "file", "mongo"):
        t = "none"
    return SaveSpec(
        type=t,  # type: ignore[arg-type]
        filename=(save.get("filename") or None),
        run_dir=(save.get("run_dir") or None),
        mongo_db=(save.get("mongo_db") or None),
        mongo_collection=(save.get("mongo_collection") or None),
    )


def _infer_target(tool: str, args: list[str], stdin_lines: list[str] | None) -> str | None:
    """
    Best-effort extraction of a "target" label for organizing output directories.
    """
    tool2 = (tool or "").strip().lower()

    def _flag_value(flags: set[str]) -> str | None:
        for i, a in enumerate(args):
            if (a or "").strip() in flags and i + 1 < len(args):
                return (args[i + 1] or "").strip()
        return None

    # Subfinder: domain is explicit
    if tool2 == "subfinder":
        d = _flag_value({"-d", "-domain", "--domain"})
        if d:
            return d.strip().strip(".").lower()

    # stdin often contains URLs/hosts (httpx/naabu/nuclei pipelines, etc.)
    if stdin_lines:
        first = (stdin_lines[0] or "").strip()
        if first:
            if "://" in first:
                try:
                    h = urlparse(first).hostname
                    if h:
                        return h.strip().strip(".").lower()
                except Exception:
                    pass
            host = first.split("/")[0].split(":")[0].strip().strip(".").lower()
            if host:
                return host

    # Fallback: URL-like args
    for a in args:
        a2 = (a or "").strip()
        if a2.startswith("http://") or a2.startswith("https://"):
            try:
                h = urlparse(a2).hostname
                if h:
                    return h.strip().strip(".").lower()
            except Exception:
                continue

    return None


def _default_run_dir(target: str | None) -> str:
    date = datetime.now().astimezone().date().isoformat()
    base = (target or "run").strip().lower()
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in base)[:200].strip("._-") or "run"
    return f"{safe}-{date}"


def _apply_default_structured_output(tool: str, args: list[str]) -> list[str]:
    # If the caller already chose JSON output, don't add anything.
    lowered = set(a.strip().lower() for a in args)
    if "-json" in lowered or "-jsonl" in lowered:
        return args

    # Common defaults to make results machine-readable.
    if tool in {"subfinder", "httpx", "naabu", "katana"}:
        return args + ["-json"]
    if tool in {"nuclei"}:
        return args + ["-jsonl"]
    return args


def _validate_safe_flags(args: list[str]) -> ValidationResult:
    for a in args:
        if (a or "").strip().lower() in _BLOCKED_FLAGS_SAFE:
            return ValidationResult(False, f"flag blocked in safe mode: {a}")
    return ValidationResult(True)


@mcp.tool()
@register_tool
def pd_supported_tools() -> dict[str, Any]:
    """List supported ProjectDiscovery tools exposed by this server."""
    return _tool_ok(sorted(_SUPPORTED_TOOLS), meta={"count": len(_SUPPORTED_TOOLS)})


@mcp.tool()
@register_tool
def pd_run(
    tool: str,
    *,
    args: list[str] | None = None,
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with explicit CLI flags/options (safe mode).

    - The tool must be one of `pd_supported_tools()`.
    - Some file/config related flags are blocked in safe mode. Use pd_run_raw if needed.
    - Results can optionally be persisted to `/data/output` or MongoDB.
    """
    return _pd_run_impl(
        tool=tool,
        args=args,
        stdin_lines=stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )


def _pd_run_impl(
    *,
    tool: str,
    args: list[str] | None,
    stdin_lines: list[str] | None,
    timeout_seconds: int | None,
    save: dict[str, Any] | None,
    safe_mode: bool,
) -> dict[str, Any]:
    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        security_event(logger, "unsupported_tool", tool=tool2)
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    args2 = args or []
    res = validate_args(args2)
    if not res.ok:
        security_event(logger, "invalid_args", error=res.message)
        return _tool_error(res.message or "invalid args")

    if safe_mode:
        safe_res = _validate_safe_flags(args2)
        if not safe_res.ok:
            security_event(logger, "blocked_flag_safe_mode", flag_error=safe_res.message)
            return _tool_error(safe_res.message or "blocked flag in safe mode")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)
    if bad_lines:
        security_event(logger, "invalid_stdin_lines", count=len(bad_lines), examples=bad_lines[:5])

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    args3 = _apply_default_structured_output(tool2, args2)

    try:
        rr = run_pd_tool(tool=tool2, args=args3, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    # Default run directory: "<target>-YYYY-MM-DD" (stored under OUTPUT_DIR, typically a Podman volume mount)
    target = _infer_target(tool2, args2, ok_lines)
    if target:
        meta["scan_target"] = target
    if save_spec.type == "file" and not save_spec.run_dir:
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)

    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_run_raw(
    tool: str,
    *,
    args: list[str],
    stdin_lines: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
    i_acknowledge_risk: bool | None = None,
) -> dict[str, Any]:
    """
    Run a supported ProjectDiscovery tool with arbitrary args (raw mode).
    Requires `i_acknowledge_risk=true`.
    """
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    vr = validate_tool_name(tool)
    if not vr.ok:
        return _tool_error(vr.message or "invalid tool")
    tool2 = tool.strip().lower()
    if tool2 not in _SUPPORTED_TOOLS:
        return _tool_error("unsupported tool", details={"supported": sorted(_SUPPORTED_TOOLS)})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    ok_lines, bad_lines = validate_lines(stdin_lines, max_lines=5000)

    try:
        if timeout_seconds is not None:
            timeout_seconds = clamp_int(int(timeout_seconds), min_value=1, max_value=3600, name="timeout_seconds")
    except Exception as e:
        return _tool_error(str(e))

    try:
        rr = run_pd_tool(tool=tool2, args=args, stdin_lines=ok_lines or None, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(
            str(e),
            details={
                "tool": tool2,
                "pd_bin_dir": os.getenv("PD_BIN_DIR", ""),
                "path": os.getenv("PATH", ""),
                "which": shutil.which(tool2),
                "hint": "If running via Podman, rebuild the image after changes; if running locally, ensure the tool is installed and on PATH.",
            },
        )

    meta = {"tool": tool2, "command": rr.command, "returncode": rr.returncode, "invalid_stdin_lines": bad_lines[:50]}
    payload = {"stdout": rr.stdout, "stderr": rr.stderr, "jsonl": rr.jsonl}

    save_spec = _parse_save_spec(save)
    if save_spec.type == "file" and not save_spec.run_dir:
        target = _infer_target(tool2, args, ok_lines)
        save_spec = SaveSpec(
            type=save_spec.type,
            filename=save_spec.filename,
            run_dir=_default_run_dir(target),
            mongo_db=save_spec.mongo_db,
            mongo_collection=save_spec.mongo_collection,
        )
    saved: dict[str, Any] | None = None
    if save_spec.type == "file":
        saved = save_to_file(spec=save_spec, payload=payload, meta=meta)
    elif save_spec.type == "mongo":
        saved = save_to_mongo(spec=save_spec, payload=payload, meta=meta)
    if saved:
        meta["saved"] = saved

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def pd_smart(
    request: str,
    *,
    domain: str | None = None,
    url: str | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Accept a vague intent (e.g. "find subdomains for example.com") and run a best-fit PD tool.
    """
    plan, errs = build_smart_plan(request, domain=domain, url=url)
    if errs:
        security_event(logger, "smart_plan_invalid", errors=errs[:10])
        return _tool_error("invalid request", details={"errors": errs[:50], "note": plan.note})
    if not plan.tool:
        return _tool_error("could not determine intent", details={"note": plan.note})
    if plan.tool not in _SUPPORTED_TOOLS:
        return _tool_error("planned tool not supported", details={"tool": plan.tool, "supported": sorted(_SUPPORTED_TOOLS)})

    # Use safe pd_run implementation path (do NOT call the @mcp.tool wrapper).
    rr = _pd_run_impl(
        tool=plan.tool,
        args=plan.args,
        stdin_lines=plan.stdin_lines,
        timeout_seconds=timeout_seconds,
        save=save,
        safe_mode=True,
    )
    # Attach plan info
    if rr.get("ok"):
        rr["meta"] = rr.get("meta") or {}
        rr["meta"]["smart_plan"] = {"intent": plan.intent, "tool": plan.tool, "args": plan.args, "note": plan.note}
    return rr


@mcp.tool()
@register_tool
def pd_diagnostics() -> dict[str, Any]:
    """
    Return basic runtime diagnostics useful for debugging tool availability inside the server.
    Does not execute any scanners; it only reports env/path visibility for supported binaries.
    """
    pd_bin_dir = os.getenv("PD_BIN_DIR", "")
    env = {
        "mcp_transport": os.getenv("MCP_TRANSPORT", ""),
        "pd_bin_dir": pd_bin_dir,
        "pdtm_bin": os.getenv("PDTM_BIN", ""),
        "path": os.getenv("PATH", ""),
    }
    which_map = {t: (shutil.which(t) or "") for t in sorted(_SUPPORTED_TOOLS)}
    missing = [t for t, p in which_map.items() if not p]
    return _tool_ok(
        {
            "env": env,
            "which": which_map,
            "missing": missing,
        },
        meta={"missing_count": len(missing), "supported_count": len(_SUPPORTED_TOOLS)},
    )


@mcp.tool()
@register_tool
def pd_results_list(
    *,
    prefix: str | None = None,
    recursive: bool = True,
    max_entries: int = 2000,
) -> dict[str, Any]:
    """
    List result files under OUTPUT_DIR (/data/output, typically a Podman volume).
    Only lists inside OUTPUT_DIR; does not access the host filesystem.
    """
    try:
        max_entries = clamp_int(int(max_entries), min_value=1, max_value=20000, name="max_entries")
        infos = list_results(prefix=prefix, recursive=bool(recursive), max_entries=max_entries)
        out = [i.__dict__ for i in infos]
        return _tool_ok(out, meta={"count": len(out), "recursive": bool(recursive)})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_read(
    path: str,
    *,
    max_bytes: int = 2_000_000,
    as_base64: bool = False,
) -> dict[str, Any]:
    """
    Read a single file from OUTPUT_DIR (/data/output). This is the supported way to
    "download" results from the Podman volume via Cursor.
    """
    try:
        max_bytes = clamp_int(int(max_bytes), min_value=1, max_value=20_000_000, name="max_bytes")
        doc = read_result_file(path=path, max_bytes=max_bytes, as_base64=bool(as_base64))
        return _tool_ok(doc, meta={"max_bytes": max_bytes})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def pd_results_export(
    path: str,
    *,
    dest_filename: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Export a single results file from OUTPUT_DIR (/data/output) to DOWNLOAD_DIR (default /data/downloads).

    NOTE: For this to land on your host filesystem, you must bind-mount a host directory
    to /data/downloads when starting the container (Cursor mcp.json / cursor-stdio.sh).
    """
    try:
        dest_dir = os.getenv("DOWNLOAD_DIR", "/data/downloads")
        doc = export_result_file(
            path=path,
            dest_dir=dest_dir,
            dest_filename=dest_filename,
            overwrite=bool(overwrite),
        )
        return _tool_ok(doc, meta={"download_dir": dest_dir})
    except Exception as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4599")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pdtm_mcp_server.server` works in Cursor without extra env.
    #
    # Containerfile explicitly sets MCP_TRANSPORT=streamable-http for HTTP deployments.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4599

    logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

### Implemented: `.env` toggle for default raw-mode acknowledgement

For `pdtm.pd_run_raw`, you can now set a global default in `Standalone_Build/.env`:

- **`i_ack_risk_default_true="true"`** (or `I_ACK_RISK_DEFAULT_TRUE="true"`)
  - If you **omit** `i_acknowledge_risk` in any `*_raw` call, it will be treated as **true**
- If it’s **false/empty**, behavior stays strict: you must pass `i_acknowledge_risk:true` per call.

I also updated `Standalone_Build/.env-sample` with:

- `i_ack_risk_default_true="false"`

### Updated `describe` output
`describe pdtm.pd_run_raw` now includes a short “Raw acknowledgement default” note explaining the env toggle.

### Note
Right now I wired this up for **`pdtm.pd_run_raw`** (as requested for `.env`-driven defaults). If you want the same behavior across **all** other `*_raw` tools (portscan/wpscan/dirscan/pentest raw tools), tell me and I’ll apply the same pattern everywhere.

---

**User**

Yes, please apply the same pattern to all of the tools

---

**Cursor**

Plan: I’ll find every `*_raw` tool that takes `i_acknowledge_risk`, change it to optional (`bool | None = None`), and route it through the same env-backed resolver you now have in `pdtm`. I’ll apply this in both the repo-root servers and the `Standalone_Build/*` copies, then run lints and a quick runtime sanity check in the shared venv.

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="portscan-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    *,
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # RustScan may optionally invoke nmap, but this MCP server doesn't do nmap-arg coercion here.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    *,
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool = False,
) -> dict[str, Any]:
    """Run naabu, rustscan, and nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    ok, err = _require_ack(i_acknowledge_risk)
    if not ok:
        return err  # type: ignore[return-value]

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        results["naabu"] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        results["rustscan"] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
    except Exception as e:
        results["rustscan"] = {"error": str(e)}

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        results["nmap"] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    return _tool_ok(
        results,
        meta={
            "invalid_targets": bad[:50],
            "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
            "nmap_coercion": (nmap_notes + nmap_notes2),
        },
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4560"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="portscan-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    *,
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # RustScan may optionally invoke nmap, but this MCP server doesn't do nmap-arg coercion here.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    *,
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
) -> dict[str, Any]:
    """Run naabu, rustscan, and nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        results["naabu"] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        results["rustscan"] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
    except Exception as e:
        results["rustscan"] = {"error": str(e)}

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        results["nmap"] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    return _tool_ok(
        results,
        meta={
            "invalid_targets": bad[:50],
            "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
            "nmap_coercion": (nmap_notes + nmap_notes2),
        },
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4560"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import validate_args, validate_url
from .wpscan_cli import WPScanNotInstalledError, run_wpscan


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="wpscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "arbitrary args can enable aggressive checks / enumeration"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def wpscan_version() -> dict[str, Any]:
    """Return WPScan version."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok({"stdout": rr.stdout.strip(), "stderr": rr.stderr.strip(), "returncode": rr.returncode})
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_debug_binary() -> dict[str, Any]:
    """Debug helper: return version output and exact command used."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok(
            {"version_stdout": rr.stdout.strip(), "version_stderr": rr.stderr.strip()},
            meta={"command": rr.command, "returncode": rr.returncode},
        )
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_scan(
    url: str,
    *,
    enumerate: str | None = None,
    stealthy: bool = False,
    plugins_detection: str | None = None,
    api_token: str | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
    max_threads: int | None = None,
    headers: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run WPScan against a target URL.

    Upstream docs: https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation

    Notes:
    - API token can be provided via env `WPSCAN_API_TOKEN` or via `api_token`.
    """

    res_url = validate_url(url)
    if not res_url.ok:
        security_event(logger, "invalid_url", url=url)
        return _tool_error(res_url.message or "invalid url")

    args: list[str] = ["--url", url]

    if stealthy:
        args.append("--stealthy")

    if enumerate:
        # wpscan expects formats like: u, u1-100, vp, vt, ap, at
        args.extend(["--enumerate", enumerate])

    if plugins_detection:
        pd = plugins_detection.strip().lower()
        if pd not in {"passive", "mixed", "aggressive"}:
            return _tool_error("plugins_detection must be one of: passive, mixed, aggressive")
        args.extend(["--plugins-detection", pd])

    # API token precedence: explicit param overrides env var.
    token = api_token if api_token is not None else os.getenv("WPSCAN_API_TOKEN")
    if token:
        args.extend(["--api-token", token])

    if proxy:
        args.extend(["--proxy", proxy])

    if user_agent:
        args.extend(["--user-agent", user_agent])

    if max_threads is not None:
        if max_threads < 1 or max_threads > 200:
            return _tool_error("max_threads must be between 1 and 200")
        args.extend(["--max-threads", str(max_threads)])

    if headers:
        # WPScan supports --headers "Header: v; Header2: v"; accept list and join with '; '
        joined = "; ".join([h.strip() for h in headers if (h or "").strip()])
        if joined:
            args.extend(["--headers", joined])

    if extra_args:
        res_args = validate_args(extra_args)
        if not res_args.ok:
            security_event(logger, "invalid_args", error=res_args.message)
            return _tool_error(res_args.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=url, data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def wpscan_scan_raw(
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run WPScan with arbitrary CLI args (no shell)."""

    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    res_args = validate_args(args)
    if not res_args.ok:
        return _tool_error(res_args.message or "invalid args")

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            # Raw mode has no structured target; store the arg vector as target for traceability.
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=" ".join(args), data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4561"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="portscan-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    *,
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # RustScan may optionally invoke nmap, but this MCP server doesn't do nmap-arg coercion here.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    *,
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
) -> dict[str, Any]:
    """Run naabu, rustscan, and nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        results["naabu"] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        results["rustscan"] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
    except Exception as e:
        results["rustscan"] = {"error": str(e)}

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        results["nmap"] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    return _tool_ok(
        results,
        meta={
            "invalid_targets": bad[:50],
            "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
            "nmap_coercion": (nmap_notes + nmap_notes2),
        },
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4560")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m portscan_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4560

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import validate_args, validate_url
from .wpscan_cli import WPScanNotInstalledError, run_wpscan


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="wpscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "arbitrary args can enable aggressive checks / enumeration"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def wpscan_version() -> dict[str, Any]:
    """Return WPScan version."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok({"stdout": rr.stdout.strip(), "stderr": rr.stderr.strip(), "returncode": rr.returncode})
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_debug_binary() -> dict[str, Any]:
    """Debug helper: return version output and exact command used."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok(
            {"version_stdout": rr.stdout.strip(), "version_stderr": rr.stderr.strip()},
            meta={"command": rr.command, "returncode": rr.returncode},
        )
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_scan(
    url: str,
    *,
    enumerate: str | None = None,
    stealthy: bool = False,
    plugins_detection: str | None = None,
    api_token: str | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
    max_threads: int | None = None,
    headers: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run WPScan against a target URL.

    Upstream docs: https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation

    Notes:
    - API token can be provided via env `WPSCAN_API_TOKEN` or via `api_token`.
    """

    res_url = validate_url(url)
    if not res_url.ok:
        security_event(logger, "invalid_url", url=url)
        return _tool_error(res_url.message or "invalid url")

    args: list[str] = ["--url", url]

    if stealthy:
        args.append("--stealthy")

    if enumerate:
        # wpscan expects formats like: u, u1-100, vp, vt, ap, at
        args.extend(["--enumerate", enumerate])

    if plugins_detection:
        pd = plugins_detection.strip().lower()
        if pd not in {"passive", "mixed", "aggressive"}:
            return _tool_error("plugins_detection must be one of: passive, mixed, aggressive")
        args.extend(["--plugins-detection", pd])

    # API token precedence: explicit param overrides env var.
    token = api_token if api_token is not None else os.getenv("WPSCAN_API_TOKEN")
    if token:
        args.extend(["--api-token", token])

    if proxy:
        args.extend(["--proxy", proxy])

    if user_agent:
        args.extend(["--user-agent", user_agent])

    if max_threads is not None:
        if max_threads < 1 or max_threads > 200:
            return _tool_error("max_threads must be between 1 and 200")
        args.extend(["--max-threads", str(max_threads)])

    if headers:
        # WPScan supports --headers "Header: v; Header2: v"; accept list and join with '; '
        joined = "; ".join([h.strip() for h in headers if (h or "").strip()])
        if joined:
            args.extend(["--headers", joined])

    if extra_args:
        res_args = validate_args(extra_args)
        if not res_args.ok:
            security_event(logger, "invalid_args", error=res_args.message)
            return _tool_error(res_args.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=url, data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def wpscan_scan_raw(
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run WPScan with arbitrary CLI args (no shell)."""

    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    res_args = validate_args(args)
    if not res_args.ok:
        return _tool_error(res_args.message or "invalid args")

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            # Raw mode has no structured target; store the arg vector as target for traceability.
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=" ".join(args), data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4561")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m wpscan_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4561

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .mongo_store import save_to_mongo_result
from .runners import BinaryNotFoundError, run_feroxbuster, run_gobuster
from .wordlists import WordlistError, list_top_level, list_wordlists, resolve_wordlist_for_use, wordlists_root


mcp = FastMCP(name="dirscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


def _norm_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        raise ValueError("url is required")
    if not (u.startswith("http://") or u.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    return u


def _clamp_int(x: int, *, min_value: int, max_value: int, name: str) -> int:
    try:
        v = int(x)
    except Exception:
        raise ValueError(f"{name} must be an integer")
    if v < min_value or v > max_value:
        raise ValueError(f"{name} must be between {min_value} and {max_value}")
    return v


@mcp.tool()
@register_tool
def wordlists_list(
    subdir: str | None = None,
    limit: int = 5000,
    include_sizes: bool = False,
) -> dict[str, Any]:
    """
    List wordlists under WORDLISTS_ROOT (default: /usr/share/wordlists).

    - Returns only relative names (no full paths).
    - `subdir` is also relative to WORDLISTS_ROOT.
    - `rockyou.txt` is not listed (if a temp copy exists); `rockyou.txt.gz` is listed.
    """
    try:
        limit = _clamp_int(limit, min_value=1, max_value=200000, name="limit")
        # Menu view: no subdir => show first-level categories and root files
        if not subdir:
            top = list_top_level(limit=limit)
            dirs = top.get("dirs") or []
            files = top.get("files") or []
            lines: list[str] = []
            lines.append("Wordlist categories (first-level directories):")
            if not dirs:
                lines.append("  (none)")
            else:
                for i, d in enumerate(dirs, 1):
                    lines.append(f"  {i:>2}. {d}/")
            if files:
                lines.append("")
                lines.append("Wordlists at root:")
                for f in files:
                    lines.append(f"  - {f}")
            lines.append("")
            lines.append("To list a category:")
            lines.append('  call dirscan.wordlists_list {"subdir":"<category>","limit":5000}')

            payload = {"stdout": "\n".join(lines) + "\n", "stderr": ""}
            return _tool_ok(
                payload,
                meta={
                    "wordlists_root": str(wordlists_root()),
                    "dirs_count": len(dirs),
                    "files_count": len(files),
                    "truncated": top.get("truncated"),
                },
            )

        listing = list_wordlists(subdir=subdir, limit=limit, include_sizes=include_sizes)
        lines: list[str] = []
        for item in (listing.get("items") or []):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            if include_sizes and ("bytes" in item):
                b = item.get("bytes")
                if isinstance(b, int):
                    lines.append(f"{name} ({b} bytes)")
                else:
                    lines.append(name)
            else:
                lines.append(name)

        payload = {"stdout": "\n".join(lines) + ("\n" if lines else ""), "stderr": ""}
        return _tool_ok(
            payload,
            meta={
                "wordlists_root": str(wordlists_root()),
                "subdir": subdir,
                "count": listing.get("count"),
                "truncated": listing.get("truncated"),
            },
        )
    except WordlistError as e:
        return _tool_error(str(e), details={"wordlists_root": str(wordlists_root())})


@mcp.tool()
@register_tool
def feroxbuster_scan(
    url: str,
    wordlist: str,
    extensions: list[str] | None = None,
    threads: int = 50,
    depth: int | None = None,
    timeout_seconds: int | None = 900,
    json_output: bool = False,
    extra_args: list[str] | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run feroxbuster against a target URL using a wordlist under WORDLISTS_ROOT.

    `wordlist` must be a relative path under WORDLISTS_ROOT, e.g. `dirb/common.txt` or `rockyou.txt.gz`.
    If `wordlist` is `rockyou.txt.gz`, it will be decompressed once per server session (warning + progress).
    """
    try:
        u = _norm_url(url)
        threads2 = _clamp_int(threads, min_value=1, max_value=2000, name="threads")
        if depth is not None:
            depth = _clamp_int(depth, min_value=0, max_value=50, name="depth")
    except ValueError as e:
        return _tool_error(str(e))

    try:
        wl_path, progress = resolve_wordlist_for_use(wordlist)
    except WordlistError as e:
        return _tool_error(str(e), details={"wordlists_root": str(wordlists_root())})

    args: list[str] = ["-u", u, "-w", str(wl_path), "-t", str(threads2)]
    if depth is not None:
        args.extend(["--depth", str(depth)])
    if extensions:
        exts = [x.strip().lstrip(".") for x in extensions if (x or "").strip()]
        if exts:
            args.extend(["-x", ",".join(exts)])
    if json_output:
        args.append("--json")
    if extra_args:
        # safe wrapper: we don't allow obvious file-write flags here
        blocked = {"-o", "--output", "--config", "--stdin"}
        if any(a in blocked for a in extra_args):
            return _tool_error("extra_args contains blocked flags (use feroxbuster_scan_raw with i_acknowledge_risk=true)")
        args.extend(extra_args)

    try:
        rr = run_feroxbuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install feroxbuster or set FEROXBUSTER_BIN"})

    stdout = rr.stdout
    if progress:
        stdout = "\n".join(progress) + "\n\n" + stdout

    payload: dict[str, Any] = {"stdout": stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command, "wordlists_root": str(wordlists_root()), "wordlist_used": str(wl_path)}

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(
                tool_name="feroxbuster",
                tool_commandline=rr.command,
                scan_target=u,
                data={"result": payload, "meta": meta},
            )
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def gobuster_scan(
    url: str,
    wordlist: str,
    extensions: list[str] | None = None,
    threads: int = 50,
    timeout_seconds: int | None = 900,
    extra_args: list[str] | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run gobuster dir against a target URL using a wordlist under WORDLISTS_ROOT.

    `wordlist` must be a relative path under WORDLISTS_ROOT, e.g. `dirb/common.txt` or `rockyou.txt.gz`.
    If `wordlist` is `rockyou.txt.gz`, it will be decompressed once per server session (warning + progress).
    """
    try:
        u = _norm_url(url)
        threads2 = _clamp_int(threads, min_value=1, max_value=2000, name="threads")
    except ValueError as e:
        return _tool_error(str(e))

    try:
        wl_path, progress = resolve_wordlist_for_use(wordlist)
    except WordlistError as e:
        return _tool_error(str(e), details={"wordlists_root": str(wordlists_root())})

    args: list[str] = ["dir", "-u", u, "-w", str(wl_path), "-t", str(threads2)]
    if extensions:
        exts = [x.strip().lstrip(".") for x in extensions if (x or "").strip()]
        if exts:
            args.extend(["-x", ",".join(exts)])
    if extra_args:
        blocked = {"-o", "--output", "--no-color"}  # keep output on stdout; allow colors via cli if desired
        if any(a in blocked for a in extra_args):
            return _tool_error("extra_args contains blocked flags (use gobuster_scan_raw with i_acknowledge_risk=true)")
        args.extend(extra_args)

    try:
        rr = run_gobuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install gobuster or set GOBUSTER_BIN"})

    stdout = rr.stdout
    if progress:
        stdout = "\n".join(progress) + "\n\n" + stdout

    payload: dict[str, Any] = {"stdout": stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command, "wordlists_root": str(wordlists_root()), "wordlist_used": str(wl_path)}

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(
                tool_name="gobuster",
                tool_commandline=rr.command,
                scan_target=u,
                data={"result": payload, "meta": meta},
            )
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def feroxbuster_scan_raw(
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run feroxbuster with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    try:
        rr = run_feroxbuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install feroxbuster or set FEROXBUSTER_BIN"})
    payload = {"stdout": rr.stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(tool_name="feroxbuster", tool_commandline=rr.command, scan_target="", data={"result": payload, "meta": meta})
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}
    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def gobuster_scan_raw(
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run gobuster with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    try:
        rr = run_gobuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install gobuster or set GOBUSTER_BIN"})
    payload = {"stdout": rr.stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(tool_name="gobuster", tool_commandline=rr.command, scan_target="", data={"result": payload, "meta": meta})
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}
    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    if transport == "stdio":
        mcp.run(transport="stdio")
        return
    # Optional HTTP transports
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4605"))
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
*** Begin Patch
*** Update File: Standalone_Build/pentest-mcp-server/src/pentest_mcp_server/server.py
@@
 def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
     if not i_acknowledge_risk:
         return False, _tool_error(
             "raw mode requires i_acknowledge_risk=true",
             details={
                 "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
             },
         )
     return True, None
+
+
+def _env_default_ack() -> bool:
+    """
+    Global default for raw-mode acknowledgement.
+
+    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
+    Supports both env var spellings:
+    - i_ack_risk_default_true
+    - I_ACK_RISK_DEFAULT_TRUE
+    """
+    raw = os.getenv("i_ack_risk_default_true", "").strip()
+    if not raw:
+        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
+    if not raw:
+        return False
+    return raw.lower() in {"1", "true", "yes", "y", "on"}
+
+
+def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
+    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()
@@
 def naabu_scan_raw(
     targets: list[str],
     args: list[str],
-    i_acknowledge_risk: bool = False,
+    i_acknowledge_risk: bool | None = None,
     timeout_seconds: int | None = 300,
     save: dict[str, Any] | None = None,
 ) -> dict[str, Any]:
     """Run Naabu with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
-    ok, err = _require_ack(i_acknowledge_risk)
+    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
     if not ok:
         return err  # type: ignore[return-value]
@@
 def nmap_scan_raw(
     targets: list[str],
     args: list[str],
-    i_acknowledge_risk: bool = False,
+    i_acknowledge_risk: bool | None = None,
     timeout_seconds: int | None = 900,
 ) -> dict[str, Any]:
     """Run Nmap with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
-    ok, err = _require_ack(i_acknowledge_risk)
+    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
     if not ok:
         return err  # type: ignore[return-value]
@@
 def rustscan_scan_raw(
     args: list[str],
     nmap_args: list[str] | None = None,
-    i_acknowledge_risk: bool = False,
+    i_acknowledge_risk: bool | None = None,
     timeout_seconds: int | None = 900,
 ) -> dict[str, Any]:
     """Run RustScan with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
-    ok, err = _require_ack(i_acknowledge_risk)
+    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
     if not ok:
         return err  # type: ignore[return-value]
@@
 def portscan_all(
     targets: list[str],
     nmap_style_args: list[str] | None = None,
     naabu_extra_args: list[str] | None = None,
     rustscan_extra_args: list[str] | None = None,
     nmap_extra_args: list[str] | None = None,
-    i_acknowledge_risk: bool = False,
+    i_acknowledge_risk: bool | None = None,
     save: dict[str, Any] | None = None,
 ) -> dict[str, Any]:
@@
-        ok, err = _require_ack(i_acknowledge_risk)
+        ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
         if not ok:
             return err  # type: ignore[return-value]
*** End Patch
```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="pentest-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

_NMAP_PORT_LINE_RE = re.compile(r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)\s*$")
_RUSTSCAN_OPEN_RE = re.compile(r"^Open\s+(?P<host>[^:]+):(?P<port>\d{1,5})\s*$")


def _parse_jsonl(stdout: str, *, max_items: int = 500) -> dict[str, Any]:
    """
    Best-effort parse of JSONL output into a small list for Mongo-friendly storage.
    """
    items: list[dict[str, Any]] = []
    total = 0
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        total += 1
        if len(items) >= max_items:
            continue
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                items.append(obj)
        except Exception:
            continue
    return {"parsed_count": total, "sample": items, "sample_limit": max_items}


def _parse_nmap_ports(stdout: str) -> list[dict[str, Any]]:
    """
    Very small parser for Nmap's human output table (best-effort).
    """
    ports: list[dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        m = _NMAP_PORT_LINE_RE.match(line.strip())
        if not m:
            continue
        try:
            p = int(m.group("port"))
        except Exception:
            continue
        ports.append(
            {
                "port": p,
                "proto": m.group("proto"),
                "state": m.group("state"),
                "service": m.group("service"),
            }
        )
    return ports


def _parse_rustscan_open_ports(stdout: str, *, max_items: int = 500) -> dict[str, Any]:
    """
    Parse lines like 'Open 192.168.1.1:443' from RustScan output (best-effort).
    """
    out: list[dict[str, Any]] = []
    total = 0
    for line in (stdout or "").splitlines():
        m = _RUSTSCAN_OPEN_RE.match(line.strip())
        if not m:
            continue
        total += 1
        if len(out) >= max_items:
            continue
        try:
            port = int(m.group("port"))
        except Exception:
            continue
        out.append({"host": m.group("host"), "port": port})
    return {"parsed_count": total, "sample": out, "sample_limit": max_items}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = 300,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Naabu against targets with common structured options (safe wrapper)."""
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    jsonl = _parse_jsonl(rr.stdout)
    if jsonl.get("sample"):
        payload["jsonl"] = jsonl
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 300,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Naabu with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    jsonl = _parse_jsonl(rr.stdout)
    if jsonl.get("sample"):
        payload["jsonl"] = jsonl
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Nmap against targets (structured wrapper)."""
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    parsed_ports = _parse_nmap_ports(rr.stdout)
    if parsed_ports:
        payload["parsed"] = {"ports": parsed_ports, "count": len(parsed_ports)}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 900,
) -> dict[str, Any]:
    """Run Nmap with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run RustScan against targets with structured options (optionally passing Nmap args)."""
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    parsed = _parse_rustscan_open_ports(rr.stdout)
    if parsed.get("sample"):
        payload["parsed"] = {"open_ports": parsed}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 900,
) -> dict[str, Any]:
    """Run RustScan with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Naabu, RustScan, and Nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    # Only require explicit risk acknowledgement when the caller provides "extra" args
    # that may enable aggressive scanning or additional behaviors (e.g., nmap scripts).
    risky_tokens: set[str] = {
        "--script",
        "--script-args",
        "--script-help",
        "-o",
        "-oA",
        "-oG",
        "-oN",
        "-oX",
        "--resume",
    }
    any_extra = bool(naabu_extra_args) or bool(rustscan_extra_args) or bool(nmap_extra_args)
    style_args = [a.strip() for a in nmap_style_args2 if isinstance(a, str)]
    needs_ack = any_extra or any(a in risky_tokens for a in style_args)
    if needs_ack:
        ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
        if not ok:
            return err  # type: ignore[return-value]

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        naabu_payload: dict[str, Any] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
        jsonl = _parse_jsonl(rr1.stdout)
        if jsonl.get("sample"):
            naabu_payload["parsed"] = {"jsonl": jsonl}
        results["naabu"] = naabu_payload
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        rust_payload: dict[str, Any] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
        parsed = _parse_rustscan_open_ports(rr2.stdout)
        if parsed.get("sample"):
            rust_payload["parsed"] = {"open_ports": parsed}
        results["rustscan"] = rust_payload
    except Exception as e:
        results["rustscan"] = {"error": str(e)}
        nmap_notes = []

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        nmap_payload: dict[str, Any] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
        parsed_ports = _parse_nmap_ports(rr3.stdout)
        if parsed_ports:
            nmap_payload["parsed"] = {"ports": parsed_ports, "count": len(parsed_ports)}
        results["nmap"] = nmap_payload
    except Exception as e:
        results["nmap"] = {"error": str(e)}
        nmap_notes2 = []

    meta: dict[str, Any] = {
        "invalid_targets": bad[:50],
        "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
        "nmap_coercion": (nmap_notes + nmap_notes2),
    }

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            tool_commandline = {
                "naabu": results.get("naabu", {}).get("command") if isinstance(results.get("naabu"), dict) else None,
                "rustscan": results.get("rustscan", {}).get("command") if isinstance(results.get("rustscan"), dict) else None,
                "nmap": results.get("nmap", {}).get("command") if isinstance(results.get("nmap"), dict) else None,
            }
            saved = save_to_mongo_result(
                tool_name="portscan_all",
                tool_commandline=tool_commandline,
                scan_target=",".join(ok_targets),
                data={"result": results, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(results, meta=meta)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4598")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pentest_mcp_server.server` works in Cursor without extra env.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4598

    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="portscan-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    if fn.__name__.endswith("_raw") and "i_acknowledge_risk" in getattr(fn, "__annotations__", {}):
        doc = (doc or "").rstrip() + (
            "\n\nRaw acknowledgement default\n\n"
            "You may omit `i_acknowledge_risk` if you set env `i_ack_risk_default_true=true` "
            "(or `I_ACK_RISK_DEFAULT_TRUE=true`)."
        )
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    *,
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # RustScan may optionally invoke nmap, but this MCP server doesn't do nmap-arg coercion here.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    *,
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
) -> dict[str, Any]:
    """Run naabu, rustscan, and nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        results["naabu"] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        results["rustscan"] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
    except Exception as e:
        results["rustscan"] = {"error": str(e)}

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        results["nmap"] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    return _tool_ok(
        results,
        meta={
            "invalid_targets": bad[:50],
            "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
            "nmap_coercion": (nmap_notes + nmap_notes2),
        },
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4560"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import validate_args, validate_url
from .wpscan_cli import WPScanNotInstalledError, run_wpscan


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="wpscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    if fn.__name__.endswith("_raw") and "i_acknowledge_risk" in getattr(fn, "__annotations__", {}):
        doc = (doc or "").rstrip() + (
            "\n\nRaw acknowledgement default\n\n"
            "You may omit `i_acknowledge_risk` if you set env `i_ack_risk_default_true=true` "
            "(or `I_ACK_RISK_DEFAULT_TRUE=true`)."
        )
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "arbitrary args can enable aggressive checks / enumeration"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def wpscan_version() -> dict[str, Any]:
    """Return WPScan version."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok({"stdout": rr.stdout.strip(), "stderr": rr.stderr.strip(), "returncode": rr.returncode})
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_debug_binary() -> dict[str, Any]:
    """Debug helper: return version output and exact command used."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok(
            {"version_stdout": rr.stdout.strip(), "version_stderr": rr.stderr.strip()},
            meta={"command": rr.command, "returncode": rr.returncode},
        )
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_scan(
    url: str,
    *,
    enumerate: str | None = None,
    stealthy: bool = False,
    plugins_detection: str | None = None,
    api_token: str | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
    max_threads: int | None = None,
    headers: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run WPScan against a target URL.

    Upstream docs: https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation

    Notes:
    - API token can be provided via env `WPSCAN_API_TOKEN` or via `api_token`.
    """

    res_url = validate_url(url)
    if not res_url.ok:
        security_event(logger, "invalid_url", url=url)
        return _tool_error(res_url.message or "invalid url")

    args: list[str] = ["--url", url]

    if stealthy:
        args.append("--stealthy")

    if enumerate:
        # wpscan expects formats like: u, u1-100, vp, vt, ap, at
        args.extend(["--enumerate", enumerate])

    if plugins_detection:
        pd = plugins_detection.strip().lower()
        if pd not in {"passive", "mixed", "aggressive"}:
            return _tool_error("plugins_detection must be one of: passive, mixed, aggressive")
        args.extend(["--plugins-detection", pd])

    # API token precedence: explicit param overrides env var.
    token = api_token if api_token is not None else os.getenv("WPSCAN_API_TOKEN")
    if token:
        args.extend(["--api-token", token])

    if proxy:
        args.extend(["--proxy", proxy])

    if user_agent:
        args.extend(["--user-agent", user_agent])

    if max_threads is not None:
        if max_threads < 1 or max_threads > 200:
            return _tool_error("max_threads must be between 1 and 200")
        args.extend(["--max-threads", str(max_threads)])

    if headers:
        # WPScan supports --headers "Header: v; Header2: v"; accept list and join with '; '
        joined = "; ".join([h.strip() for h in headers if (h or "").strip()])
        if joined:
            args.extend(["--headers", joined])

    if extra_args:
        res_args = validate_args(extra_args)
        if not res_args.ok:
            security_event(logger, "invalid_args", error=res_args.message)
            return _tool_error(res_args.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=url, data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def wpscan_scan_raw(
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run WPScan with arbitrary CLI args (no shell)."""

    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    res_args = validate_args(args)
    if not res_args.ok:
        return _tool_error(res_args.message or "invalid args")

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            # Raw mode has no structured target; store the arg vector as target for traceability.
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=" ".join(args), data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4561"))
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="portscan-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    if fn.__name__.endswith("_raw") and "i_acknowledge_risk" in getattr(fn, "__annotations__", {}):
        doc = (doc or "").rstrip() + (
            "\n\nRaw acknowledgement default\n\n"
            "You may omit `i_acknowledge_risk` if you set env `i_ack_risk_default_true=true` "
            "(or `I_ACK_RISK_DEFAULT_TRUE=true`)."
        )
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # Naabu does not use nmap coercion; keep field for compatibility but default empty.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    *,
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    # RustScan may optionally invoke nmap, but this MCP server doesn't do nmap-arg coercion here.
    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"stdout": rr.stdout, "stderr": rr.stderr},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    *,
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    *,
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
) -> dict[str, Any]:
    """Run naabu, rustscan, and nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        results["naabu"] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        results["rustscan"] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
    except Exception as e:
        results["rustscan"] = {"error": str(e)}

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        results["nmap"] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
    except Exception as e:
        results["nmap"] = {"error": str(e)}

    return _tool_ok(
        results,
        meta={
            "invalid_targets": bad[:50],
            "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
            "nmap_coercion": (nmap_notes + nmap_notes2),
        },
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4560")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m portscan_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4560

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .validation import validate_args, validate_url
from .wpscan_cli import WPScanNotInstalledError, run_wpscan


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="wpscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    if fn.__name__.endswith("_raw") and "i_acknowledge_risk" in getattr(fn, "__annotations__", {}):
        doc = (doc or "").rstrip() + (
            "\n\nRaw acknowledgement default\n\n"
            "You may omit `i_acknowledge_risk` if you set env `i_ack_risk_default_true=true` "
            "(or `I_ACK_RISK_DEFAULT_TRUE=true`)."
        )
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={"reason": "arbitrary args can enable aggressive checks / enumeration"},
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def wpscan_version() -> dict[str, Any]:
    """Return WPScan version."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok({"stdout": rr.stdout.strip(), "stderr": rr.stderr.strip(), "returncode": rr.returncode})
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_debug_binary() -> dict[str, Any]:
    """Debug helper: return version output and exact command used."""
    try:
        rr = run_wpscan(args=["--version"], timeout_seconds=60)
        return _tool_ok(
            {"version_stdout": rr.stdout.strip(), "version_stderr": rr.stderr.strip()},
            meta={"command": rr.command, "returncode": rr.returncode},
        )
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))


@mcp.tool()
@register_tool
def wpscan_scan(
    url: str,
    *,
    enumerate: str | None = None,
    stealthy: bool = False,
    plugins_detection: str | None = None,
    api_token: str | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
    max_threads: int | None = None,
    headers: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run WPScan against a target URL.

    Upstream docs: https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation

    Notes:
    - API token can be provided via env `WPSCAN_API_TOKEN` or via `api_token`.
    """

    res_url = validate_url(url)
    if not res_url.ok:
        security_event(logger, "invalid_url", url=url)
        return _tool_error(res_url.message or "invalid url")

    args: list[str] = ["--url", url]

    if stealthy:
        args.append("--stealthy")

    if enumerate:
        # wpscan expects formats like: u, u1-100, vp, vt, ap, at
        args.extend(["--enumerate", enumerate])

    if plugins_detection:
        pd = plugins_detection.strip().lower()
        if pd not in {"passive", "mixed", "aggressive"}:
            return _tool_error("plugins_detection must be one of: passive, mixed, aggressive")
        args.extend(["--plugins-detection", pd])

    # API token precedence: explicit param overrides env var.
    token = api_token if api_token is not None else os.getenv("WPSCAN_API_TOKEN")
    if token:
        args.extend(["--api-token", token])

    if proxy:
        args.extend(["--proxy", proxy])

    if user_agent:
        args.extend(["--user-agent", user_agent])

    if max_threads is not None:
        if max_threads < 1 or max_threads > 200:
            return _tool_error("max_threads must be between 1 and 200")
        args.extend(["--max-threads", str(max_threads)])

    if headers:
        # WPScan supports --headers "Header: v; Header2: v"; accept list and join with '; '
        joined = "; ".join([h.strip() for h in headers if (h or "").strip()])
        if joined:
            args.extend(["--headers", joined])

    if extra_args:
        res_args = validate_args(extra_args)
        if not res_args.ok:
            security_event(logger, "invalid_args", error=res_args.message)
            return _tool_error(res_args.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        security_event(logger, "wpscan_not_installed", error=str(e))
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=url, data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def wpscan_scan_raw(
    *,
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run WPScan with arbitrary CLI args (no shell)."""

    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    res_args = validate_args(args)
    if not res_args.ok:
        return _tool_error(res_args.message or "invalid args")

    try:
        rr = run_wpscan(args=args, timeout_seconds=timeout_seconds)
    except WPScanNotInstalledError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            # Raw mode has no structured target; store the arg vector as target for traceability.
            saved = save_to_mongo_result(tool_name="wpscan", tool_commandline=rr.command, scan_target=" ".join(args), data={"stdout": rr.stdout, "stderr": rr.stderr})
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta=meta,
    )


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4561")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m wpscan_mcp_server.server` works in Cursor without extra env.
    #
    # The Podman-oriented version can still explicitly set MCP_TRANSPORT=streamable-http.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4561

    # FastMCP supports http-like transports which do accept host/port/path.
    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    # Fall back defensively to a known-good default.
    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()

```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .mongo_store import save_to_mongo_result
from .runners import BinaryNotFoundError, run_feroxbuster, run_gobuster
from .wordlists import WordlistError, list_top_level, list_wordlists, resolve_wordlist_for_use, wordlists_root


mcp = FastMCP(name="dirscan")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    doc = inspect.getdoc(fn) or ""
    if fn.__name__.endswith("_raw") and "i_acknowledge_risk" in getattr(fn, "__annotations__", {}):
        doc = (doc or "").rstrip() + (
            "\n\nRaw acknowledgement default\n\n"
            "You may omit `i_acknowledge_risk` if you set env `i_ack_risk_default_true=true` "
            "(or `I_ACK_RISK_DEFAULT_TRUE=true`)."
        )
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


def _norm_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        raise ValueError("url is required")
    if not (u.startswith("http://") or u.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    return u


def _clamp_int(x: int, *, min_value: int, max_value: int, name: str) -> int:
    try:
        v = int(x)
    except Exception:
        raise ValueError(f"{name} must be an integer")
    if v < min_value or v > max_value:
        raise ValueError(f"{name} must be between {min_value} and {max_value}")
    return v


@mcp.tool()
@register_tool
def wordlists_list(
    subdir: str | None = None,
    limit: int = 5000,
    include_sizes: bool = False,
) -> dict[str, Any]:
    """
    List wordlists under WORDLISTS_ROOT (default: /usr/share/wordlists).

    - Returns only relative names (no full paths).
    - `subdir` is also relative to WORDLISTS_ROOT.
    - `rockyou.txt` is not listed (if a temp copy exists); `rockyou.txt.gz` is listed.
    """
    try:
        limit = _clamp_int(limit, min_value=1, max_value=200000, name="limit")
        # Menu view: no subdir => show first-level categories and root files
        if not subdir:
            top = list_top_level(limit=limit)
            dirs = top.get("dirs") or []
            files = top.get("files") or []
            lines: list[str] = []
            lines.append("Wordlist categories (first-level directories):")
            if not dirs:
                lines.append("  (none)")
            else:
                for i, d in enumerate(dirs, 1):
                    lines.append(f"  {i:>2}. {d}/")
            if files:
                lines.append("")
                lines.append("Wordlists at root:")
                for f in files:
                    lines.append(f"  - {f}")
            lines.append("")
            lines.append("To list a category:")
            lines.append('  call dirscan.wordlists_list {"subdir":"<category>","limit":5000}')

            payload = {"stdout": "\n".join(lines) + "\n", "stderr": ""}
            return _tool_ok(
                payload,
                meta={
                    "wordlists_root": str(wordlists_root()),
                    "dirs_count": len(dirs),
                    "files_count": len(files),
                    "truncated": top.get("truncated"),
                },
            )

        listing = list_wordlists(subdir=subdir, limit=limit, include_sizes=include_sizes)
        lines: list[str] = []
        for item in (listing.get("items") or []):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            if include_sizes and ("bytes" in item):
                b = item.get("bytes")
                if isinstance(b, int):
                    lines.append(f"{name} ({b} bytes)")
                else:
                    lines.append(name)
            else:
                lines.append(name)

        payload = {"stdout": "\n".join(lines) + ("\n" if lines else ""), "stderr": ""}
        return _tool_ok(
            payload,
            meta={
                "wordlists_root": str(wordlists_root()),
                "subdir": subdir,
                "count": listing.get("count"),
                "truncated": listing.get("truncated"),
            },
        )
    except WordlistError as e:
        return _tool_error(str(e), details={"wordlists_root": str(wordlists_root())})


@mcp.tool()
@register_tool
def feroxbuster_scan(
    url: str,
    wordlist: str,
    extensions: list[str] | None = None,
    threads: int = 50,
    depth: int | None = None,
    timeout_seconds: int | None = 900,
    json_output: bool = False,
    extra_args: list[str] | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run feroxbuster against a target URL using a wordlist under WORDLISTS_ROOT.

    `wordlist` must be a relative path under WORDLISTS_ROOT, e.g. `dirb/common.txt` or `rockyou.txt.gz`.
    If `wordlist` is `rockyou.txt.gz`, it will be decompressed once per server session (warning + progress).
    """
    try:
        u = _norm_url(url)
        threads2 = _clamp_int(threads, min_value=1, max_value=2000, name="threads")
        if depth is not None:
            depth = _clamp_int(depth, min_value=0, max_value=50, name="depth")
    except ValueError as e:
        return _tool_error(str(e))

    try:
        wl_path, progress = resolve_wordlist_for_use(wordlist)
    except WordlistError as e:
        return _tool_error(str(e), details={"wordlists_root": str(wordlists_root())})

    args: list[str] = ["-u", u, "-w", str(wl_path), "-t", str(threads2)]
    if depth is not None:
        args.extend(["--depth", str(depth)])
    if extensions:
        exts = [x.strip().lstrip(".") for x in extensions if (x or "").strip()]
        if exts:
            args.extend(["-x", ",".join(exts)])
    if json_output:
        args.append("--json")
    if extra_args:
        # safe wrapper: we don't allow obvious file-write flags here
        blocked = {"-o", "--output", "--config", "--stdin"}
        if any(a in blocked for a in extra_args):
            return _tool_error("extra_args contains blocked flags (use feroxbuster_scan_raw with i_acknowledge_risk=true)")
        args.extend(extra_args)

    try:
        rr = run_feroxbuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install feroxbuster or set FEROXBUSTER_BIN"})

    stdout = rr.stdout
    if progress:
        stdout = "\n".join(progress) + "\n\n" + stdout

    payload: dict[str, Any] = {"stdout": stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command, "wordlists_root": str(wordlists_root()), "wordlist_used": str(wl_path)}

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(
                tool_name="feroxbuster",
                tool_commandline=rr.command,
                scan_target=u,
                data={"result": payload, "meta": meta},
            )
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def gobuster_scan(
    url: str,
    wordlist: str,
    extensions: list[str] | None = None,
    threads: int = 50,
    timeout_seconds: int | None = 900,
    extra_args: list[str] | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run gobuster dir against a target URL using a wordlist under WORDLISTS_ROOT.

    `wordlist` must be a relative path under WORDLISTS_ROOT, e.g. `dirb/common.txt` or `rockyou.txt.gz`.
    If `wordlist` is `rockyou.txt.gz`, it will be decompressed once per server session (warning + progress).
    """
    try:
        u = _norm_url(url)
        threads2 = _clamp_int(threads, min_value=1, max_value=2000, name="threads")
    except ValueError as e:
        return _tool_error(str(e))

    try:
        wl_path, progress = resolve_wordlist_for_use(wordlist)
    except WordlistError as e:
        return _tool_error(str(e), details={"wordlists_root": str(wordlists_root())})

    args: list[str] = ["dir", "-u", u, "-w", str(wl_path), "-t", str(threads2)]
    if extensions:
        exts = [x.strip().lstrip(".") for x in extensions if (x or "").strip()]
        if exts:
            args.extend(["-x", ",".join(exts)])
    if extra_args:
        blocked = {"-o", "--output", "--no-color"}  # keep output on stdout; allow colors via cli if desired
        if any(a in blocked for a in extra_args):
            return _tool_error("extra_args contains blocked flags (use gobuster_scan_raw with i_acknowledge_risk=true)")
        args.extend(extra_args)

    try:
        rr = run_gobuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install gobuster or set GOBUSTER_BIN"})

    stdout = rr.stdout
    if progress:
        stdout = "\n".join(progress) + "\n\n" + stdout

    payload: dict[str, Any] = {"stdout": stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command, "wordlists_root": str(wordlists_root()), "wordlist_used": str(wl_path)}

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(
                tool_name="gobuster",
                tool_commandline=rr.command,
                scan_target=u,
                data={"result": payload, "meta": meta},
            )
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def feroxbuster_scan_raw(
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run feroxbuster with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    try:
        rr = run_feroxbuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install feroxbuster or set FEROXBUSTER_BIN"})
    payload = {"stdout": rr.stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(tool_name="feroxbuster", tool_commandline=rr.command, scan_target="", data={"result": payload, "meta": meta})
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}
    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def gobuster_scan_raw(
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run gobuster with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    try:
        rr = run_gobuster(args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e), details={"hint": "install gobuster or set GOBUSTER_BIN"})
    payload = {"stdout": rr.stdout, "stderr": rr.stderr}
    meta: dict[str, Any] = {"returncode": rr.returncode, "command": rr.command}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            meta["saved"] = save_to_mongo_result(tool_name="gobuster", tool_commandline=rr.command, scan_target="", data={"result": payload, "meta": meta})
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}
    return _tool_ok(payload, meta=meta)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    if transport == "stdio":
        mcp.run(transport="stdio")
        return
    # Optional HTTP transports
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "4605"))
    path = os.getenv("MCP_PATH", "").strip() or None
    mcp.run(transport=transport, host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

```python
from __future__ import annotations

import inspect
import json
import os
import re
from typing import Any

from fastmcp import FastMCP

from .logging_utils import configure_logging, get_logger, security_event
from .mongo_store import save_to_mongo_result
from .normalize import coerce_nmap_unprivileged, normalize_nmap_style_args
from .runners import BinaryNotFoundError, run_naabu, run_nmap, run_rustscan
from .validation import clamp_int, normalize_rustscan_ports, validate_args, validate_targets


configure_logging()
logger = get_logger(__name__)

mcp = FastMCP(name="pentest-suite")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}

_NMAP_PORT_LINE_RE = re.compile(r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)\s*$")
_RUSTSCAN_OPEN_RE = re.compile(r"^Open\s+(?P<host>[^:]+):(?P<port>\d{1,5})\s*$")


def _parse_jsonl(stdout: str, *, max_items: int = 500) -> dict[str, Any]:
    """
    Best-effort parse of JSONL output into a small list for Mongo-friendly storage.
    """
    items: list[dict[str, Any]] = []
    total = 0
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        total += 1
        if len(items) >= max_items:
            continue
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                items.append(obj)
        except Exception:
            continue
    return {"parsed_count": total, "sample": items, "sample_limit": max_items}


def _parse_nmap_ports(stdout: str) -> list[dict[str, Any]]:
    """
    Very small parser for Nmap's human output table (best-effort).
    """
    ports: list[dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        m = _NMAP_PORT_LINE_RE.match(line.strip())
        if not m:
            continue
        try:
            p = int(m.group("port"))
        except Exception:
            continue
        ports.append(
            {
                "port": p,
                "proto": m.group("proto"),
                "state": m.group("state"),
                "service": m.group("service"),
            }
        )
    return ports


def _parse_rustscan_open_ports(stdout: str, *, max_items: int = 500) -> dict[str, Any]:
    """
    Parse lines like 'Open 192.168.1.1:443' from RustScan output (best-effort).
    """
    out: list[dict[str, Any]] = []
    total = 0
    for line in (stdout or "").splitlines():
        m = _RUSTSCAN_OPEN_RE.match(line.strip())
        if not m:
            continue
        total += 1
        if len(out) >= max_items:
            continue
        try:
            port = int(m.group("port"))
        except Exception:
            continue
        out.append({"host": m.group("host"), "port": port})
    return {"parsed_count": total, "sample": out, "sample_limit": max_items}


def _type_repr(t: Any) -> str | None:
    if t is inspect._empty:
        return None
    try:
        name = getattr(t, "__name__", None)
        if isinstance(name, str) and name:
            return name
    except Exception:
        pass
    return str(t)


def _jsonable_default(v: Any) -> Any:
    if v is inspect._empty:
        return None
    try:
        json.dumps(v, default=str)
        return v
    except TypeError:
        return repr(v)


def register_tool(fn):
    """
    Decorator that records tool metadata (name/docstring/signature) so we can expose
    `list_tools`/`describe_tool` as normal MCP tools.
    """
    doc = inspect.getdoc(fn) or ""
    if fn.__name__.endswith("_raw") and "i_acknowledge_risk" in getattr(fn, "__annotations__", {}):
        doc = (doc or "").rstrip() + (
            "\n\nRaw acknowledgement default\n\n"
            "You may omit `i_acknowledge_risk` if you set env `i_ack_risk_default_true=true` "
            "(or `I_ACK_RISK_DEFAULT_TRUE=true`)."
        )
        try:
            fn.__doc__ = doc
        except Exception:
            pass
    sig = inspect.signature(fn)
    try:
        from typing import get_type_hints

        hints = get_type_hints(fn, include_extras=True)
    except Exception:
        hints = {}

    # FastMCP schema generation treats future-annotations (string annotations) as unknown and
    # can mark optional params as required. Resolve and attach real annotations before wrapping.
    if hints:
        try:
            fn.__annotations__ = dict(hints)
        except Exception:
            pass

    params: list[dict[str, Any]] = []
    for param_name, p in sig.parameters.items():
        ann = hints.get(param_name, p.annotation)
        required = p.default is inspect._empty and p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
        params.append(
            {
                "name": param_name,
                "type": _type_repr(ann),
                "required": required,
                "default": _jsonable_default(p.default) if p.default is not inspect._empty else None,
                "kind": str(p.kind).split(".")[-1],
            }
        )

    ret_ann = hints.get("return", sig.return_annotation)
    _TOOL_REGISTRY[fn.__name__] = {
        "name": fn.__name__,
        "description": doc,
        "params": params,
        "return_type": _type_repr(ret_ann),
    }
    return fn


def _tool_error(message: str, *, details: Any | None = None) -> dict[str, Any]:
    return {"ok": False, "error": message, "details": details}


def _tool_ok(result: Any, *, meta: Any | None = None) -> dict[str, Any]:
    return {"ok": True, "result": result, "meta": meta or {}}


def _require_ack(i_acknowledge_risk: bool) -> tuple[bool, dict[str, Any] | None]:
    if not i_acknowledge_risk:
        return False, _tool_error(
            "raw mode requires i_acknowledge_risk=true",
            details={
                "reason": "raw flags can perform aggressive scanning, file writes, and script execution",
            },
        )
    return True, None


def _env_default_ack() -> bool:
    """
    Global default for raw-mode acknowledgement.

    If set, allows users to omit `i_acknowledge_risk` from *_raw tool calls.
    Supports both env var spellings:
    - i_ack_risk_default_true
    - I_ACK_RISK_DEFAULT_TRUE
    """
    raw = os.getenv("i_ack_risk_default_true", "").strip()
    if not raw:
        raw = os.getenv("I_ACK_RISK_DEFAULT_TRUE", "").strip()
    if not raw:
        return False
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _resolve_ack(i_acknowledge_risk: bool | None) -> bool:
    return bool(i_acknowledge_risk) if i_acknowledge_risk is not None else _env_default_ack()


@mcp.tool()
@register_tool
def naabu_scan(
    targets: list[str],
    ports: str | None = None,
    top_ports: int | None = None,
    rate: int = 1000,
    exclude_ports: str | None = None,
    json_output: bool = True,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = 300,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Naabu against targets with common structured options (safe wrapper)."""
    ok_targets, bad = validate_targets(targets)
    if bad:
        security_event(logger, "invalid_targets", examples=bad[:5], count=len(bad))
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    try:
        rate = clamp_int(rate, min_value=1, max_value=5_000_000, name="rate")
        if top_ports is not None:
            top_ports = clamp_int(top_ports, min_value=1, max_value=65535, name="top_ports")
    except ValueError as e:
        return _tool_error(str(e))

    args: list[str] = ["-silent", "-rate", str(rate)]
    if json_output:
        args.append("-json")
    if ports:
        args.extend(["-p", ports])
    if top_ports is not None:
        args.extend(["-top-ports", str(top_ports)])
    if exclude_ports:
        args.extend(["-exclude-ports", exclude_ports])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            security_event(logger, "invalid_args", error=res.message)
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    jsonl = _parse_jsonl(rr.stdout)
    if jsonl.get("sample"):
        payload["jsonl"] = jsonl
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def naabu_scan_raw(
    targets: list[str],
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 300,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Naabu with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_naabu(targets=ok_targets, args=args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    jsonl = _parse_jsonl(rr.stdout)
    if jsonl.get("sample"):
        payload["jsonl"] = jsonl
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="naabu",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan(
    targets: list[str],
    args: list[str] | None = None,
    force_unprivileged: bool = True,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Nmap against targets (structured wrapper)."""
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args2 = args or []

    notes: list[str] = []
    if force_unprivileged and os.getenv("NMAP_FORCE_UNPRIVILEGED", "1").strip() != "0":
        args2, notes = coerce_nmap_unprivileged(args2)
    res = validate_args(args2)
    if not res.ok:
        return _tool_error(res.message or "invalid args")

    try:
        rr = run_nmap(targets=ok_targets, args=args2, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    parsed_ports = _parse_nmap_ports(rr.stdout)
    if parsed_ports:
        payload["parsed"] = {"ports": parsed_ports, "count": len(parsed_ports)}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="nmap",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def nmap_scan_raw(
    targets: list[str],
    args: list[str],
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 900,
) -> dict[str, Any]:
    """Run Nmap with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]
    return nmap_scan(targets, args=args, timeout_seconds=timeout_seconds)


@mcp.tool()
@register_tool
def rustscan_scan(
    targets: list[str],
    ports: str | None = None,
    batch_size: int | None = None,
    timeout_millis: int | None = None,
    nmap_args: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int | None = 900,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run RustScan against targets with structured options (optionally passing Nmap args)."""
    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    args: list[str] = []
    if ports:
        pres, pargs = normalize_rustscan_ports(ports)
        if not pres.ok:
            security_event(logger, "invalid_ports", error=pres.message, ports=ports)
            return _tool_error(pres.message or "invalid ports")
        args.extend(pargs)
    if batch_size is not None:
        try:
            batch_size = clamp_int(batch_size, min_value=1, max_value=100000, name="batch_size")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-b", str(batch_size)])
    if timeout_millis is not None:
        try:
            timeout_millis = clamp_int(timeout_millis, min_value=1, max_value=600000, name="timeout_millis")
        except ValueError as e:
            return _tool_error(str(e))
        args.extend(["-t", str(timeout_millis)])

    if extra_args:
        res = validate_args(extra_args)
        if not res.ok:
            return _tool_error(res.message or "invalid args")
        args.extend(extra_args)

    if nmap_args:
        res = validate_args(nmap_args)
        if not res.ok:
            return _tool_error(res.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    meta = {"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes}
    payload: dict[str, Any] = {"stdout": rr.stdout, "stderr": rr.stderr}
    parsed = _parse_rustscan_open_ports(rr.stdout)
    if parsed.get("sample"):
        payload["parsed"] = {"open_ports": parsed}
    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            saved = save_to_mongo_result(
                tool_name="rustscan",
                tool_commandline=rr.command,
                scan_target=",".join(ok_targets),
                data={"result": payload, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(
        payload,
        meta=meta,
    )


@mcp.tool()
@register_tool
def rustscan_scan_raw(
    targets: list[str],
    args: list[str],
    nmap_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
    timeout_seconds: int | None = 900,
) -> dict[str, Any]:
    """Run RustScan with arbitrary CLI args (no shell). Requires `i_acknowledge_risk=true`."""
    ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
    if not ok:
        return err  # type: ignore[return-value]

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    res = validate_args(args)
    if not res.ok:
        return _tool_error(res.message or "invalid args")
    if nmap_args:
        res2 = validate_args(nmap_args)
        if not res2.ok:
            return _tool_error(res2.message or "invalid nmap_args")

    try:
        rr = run_rustscan(targets=ok_targets, args=args, nmap_args=nmap_args, timeout_seconds=timeout_seconds)
    except BinaryNotFoundError as e:
        return _tool_error(str(e))

    notes: list[str] = []
    return _tool_ok(
        {"stdout": rr.stdout, "stderr": rr.stderr},
        meta={"returncode": rr.returncode, "command": rr.command, "invalid_targets": bad[:50], "nmap_notes": notes},
    )


@mcp.tool()
@register_tool
def portscan_all(
    targets: list[str],
    nmap_style_args: list[str] | None = None,
    naabu_extra_args: list[str] | None = None,
    rustscan_extra_args: list[str] | None = None,
    nmap_extra_args: list[str] | None = None,
    i_acknowledge_risk: bool | None = None,
    save: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Naabu, RustScan, and Nmap with a unified Nmap-style option set (best-effort mapping)."""

    ok_targets, bad = validate_targets(targets)
    if not ok_targets:
        return _tool_error("no valid targets", details={"invalid": bad[:50]})

    nmap_style_args2 = nmap_style_args or []
    res = validate_args(nmap_style_args2)
    if not res.ok:
        return _tool_error(res.message or "invalid nmap_style_args")

    # Only require explicit risk acknowledgement when the caller provides "extra" args
    # that may enable aggressive scanning or additional behaviors (e.g., nmap scripts).
    risky_tokens: set[str] = {
        "--script",
        "--script-args",
        "--script-help",
        "-o",
        "-oA",
        "-oG",
        "-oN",
        "-oX",
        "--resume",
    }
    any_extra = bool(naabu_extra_args) or bool(rustscan_extra_args) or bool(nmap_extra_args)
    style_args = [a.strip() for a in nmap_style_args2 if isinstance(a, str)]
    needs_ack = any_extra or any(a in risky_tokens for a in style_args)
    if needs_ack:
        ok, err = _require_ack(_resolve_ack(i_acknowledge_risk))
        if not ok:
            return err  # type: ignore[return-value]

    norm, nmap_remaining = normalize_nmap_style_args(nmap_style_args2)

    # Naabu mapping
    naabu_args: list[str] = ["-silent", "-json"]
    if norm.ports:
        naabu_args.extend(["-p", norm.ports])
    if norm.top_ports is not None:
        naabu_args.extend(["-top-ports", str(norm.top_ports)])
    if norm.min_rate is not None:
        naabu_args.extend(["-rate", str(norm.min_rate)])
    if naabu_extra_args:
        ra = validate_args(naabu_extra_args)
        if not ra.ok:
            return _tool_error(ra.message or "invalid naabu_extra_args")
        naabu_args.extend(naabu_extra_args)

    # RustScan mapping
    rust_args: list[str] = []
    if norm.ports:
        pres, pargs = normalize_rustscan_ports(norm.ports)
        if not pres.ok:
            return _tool_error(pres.message or "invalid ports")
        rust_args.extend(pargs)
    if rustscan_extra_args:
        ra2 = validate_args(rustscan_extra_args)
        if not ra2.ok:
            return _tool_error(ra2.message or "invalid rustscan_extra_args")
        rust_args.extend(rustscan_extra_args)

    # Nmap args
    nmap_args: list[str] = nmap_remaining
    if nmap_extra_args:
        rn = validate_args(nmap_extra_args)
        if not rn.ok:
            return _tool_error(rn.message or "invalid nmap_extra_args")
        nmap_args.extend(nmap_extra_args)

    results: dict[str, Any] = {}

    try:
        rr1 = run_naabu(targets=ok_targets, args=naabu_args, timeout_seconds=300)
        naabu_payload: dict[str, Any] = {"stdout": rr1.stdout, "stderr": rr1.stderr, "returncode": rr1.returncode, "command": rr1.command}
        jsonl = _parse_jsonl(rr1.stdout)
        if jsonl.get("sample"):
            naabu_payload["parsed"] = {"jsonl": jsonl}
        results["naabu"] = naabu_payload
    except Exception as e:
        results["naabu"] = {"error": str(e)}

    try:
        nmap_args_safe, nmap_notes = coerce_nmap_unprivileged(nmap_args)
        rr2 = run_rustscan(targets=ok_targets, args=rust_args, nmap_args=nmap_args_safe, timeout_seconds=900)
        rust_payload: dict[str, Any] = {"stdout": rr2.stdout, "stderr": rr2.stderr, "returncode": rr2.returncode, "command": rr2.command}
        parsed = _parse_rustscan_open_ports(rr2.stdout)
        if parsed.get("sample"):
            rust_payload["parsed"] = {"open_ports": parsed}
        results["rustscan"] = rust_payload
    except Exception as e:
        results["rustscan"] = {"error": str(e)}
        nmap_notes = []

    try:
        nmap_args_final, nmap_notes2 = coerce_nmap_unprivileged(nmap_args)
        rr3 = run_nmap(targets=ok_targets, args=nmap_args_final, timeout_seconds=900)
        nmap_payload: dict[str, Any] = {"stdout": rr3.stdout, "stderr": rr3.stderr, "returncode": rr3.returncode, "command": rr3.command}
        parsed_ports = _parse_nmap_ports(rr3.stdout)
        if parsed_ports:
            nmap_payload["parsed"] = {"ports": parsed_ports, "count": len(parsed_ports)}
        results["nmap"] = nmap_payload
    except Exception as e:
        results["nmap"] = {"error": str(e)}
        nmap_notes2 = []

    meta: dict[str, Any] = {
        "invalid_targets": bad[:50],
        "normalized": {"ports": norm.ports, "top_ports": norm.top_ports, "min_rate": norm.min_rate},
        "nmap_coercion": (nmap_notes + nmap_notes2),
    }

    if save and (save.get("type") or "").strip().lower() == "mongo":
        try:
            tool_commandline = {
                "naabu": results.get("naabu", {}).get("command") if isinstance(results.get("naabu"), dict) else None,
                "rustscan": results.get("rustscan", {}).get("command") if isinstance(results.get("rustscan"), dict) else None,
                "nmap": results.get("nmap", {}).get("command") if isinstance(results.get("nmap"), dict) else None,
            }
            saved = save_to_mongo_result(
                tool_name="portscan_all",
                tool_commandline=tool_commandline,
                scan_target=",".join(ok_targets),
                data={"result": results, "meta": meta},
            )
            meta["saved"] = saved
        except Exception as e:
            meta["saved"] = {"saved": False, "error": str(e)}

    return _tool_ok(results, meta=meta)


@mcp.tool()
@register_tool
def list_tools() -> dict[str, Any]:
    """List tool names, docstrings, and parameter metadata exposed by this MCP server."""
    tools = [_TOOL_REGISTRY[k] for k in sorted(_TOOL_REGISTRY)]
    return _tool_ok(tools, meta={"count": len(tools)})


@mcp.tool()
@register_tool
def describe_tool(name: str) -> dict[str, Any]:
    """Return detailed metadata for a single tool by its function name."""
    tool_name = (name or "").strip()
    if not tool_name:
        return _tool_error("name is required")
    if not _TOOL_NAME_RE.match(tool_name):
        security_event(logger, "invalid_tool_name", tool_name=tool_name)
        return _tool_error("invalid tool name")
    tool = _TOOL_REGISTRY.get(tool_name)
    if not tool:
        return _tool_error("unknown tool", details={"known_tools": sorted(_TOOL_REGISTRY)[:200]})
    return _tool_ok(tool)


def main() -> None:
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port_raw = os.getenv("MCP_PORT", "4598")
    # Cursor MCP "command" servers speak stdio. Default to stdio so a plain
    # `python -m pentest_mcp_server.server` works in Cursor without extra env.
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    path = os.getenv("MCP_PATH", "").strip() or None

    # FastMCP's stdio transport does not accept HTTP server args (host/port/path).
    if transport == "stdio":
        logger.info("Starting MCP server", extra={"transport": transport})
        mcp.run(transport="stdio")
        return

    try:
        port = int(port_raw)
    except ValueError:
        security_event(logger, "invalid_mcp_port", value=port_raw)
        port = 4598

    if transport in {"http", "sse", "streamable-http"}:
        logger.info("Starting MCP server", extra={"transport": transport, "host": host, "port": port, "path": path or ""})
        mcp.run(transport=transport, host=host, port=port, path=path)
        return

    security_event(logger, "unknown_mcp_transport", value=transport)
    logger.info("Starting MCP server with fallback transport", extra={"transport": "streamable-http", "host": host, "port": port, "path": path or ""})
    mcp.run(transport="streamable-http", host=host, port=port, path=path)


if __name__ == "__main__":
    main()



```

### Done: applied the `.env` default-ack pattern to **all** `*_raw` tools

Across both the repo-root servers **and** `Standalone_Build/*` copies:

- Every `*_raw` tool now accepts **`i_acknowledge_risk: bool | None = None`**
- If you **omit** `i_acknowledge_risk`, it resolves from env:
  - `i_ack_risk_default_true=true` **or** `I_ACK_RISK_DEFAULT_TRUE=true` → treated as **true**
  - otherwise → treated as **false** (you must pass `i_acknowledge_risk:true` per call)
- Any “conditional ack” wrapper (like `portscan_all`) also uses the env default when the ack is needed.

### `describe` improvements
All `*_raw` tools now append a short note:

- “You may omit `i_acknowledge_risk` if you set env `i_ack_risk_default_true=true` …”

### How to use
In `Standalone_Build/.env`:

```bash
i_ack_risk_default_true="true"
```

Then you can omit `i_acknowledge_risk` in raw calls.

You’ll need to restart the affected MCP servers (or restart `pentest-cli`) so the updated schemas/docs load.

```shellscript
i_ack_risk_default_true="true"
```

