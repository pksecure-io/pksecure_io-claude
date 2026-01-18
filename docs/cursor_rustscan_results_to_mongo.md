# RustScan results to Mongo
_Exported on 12/28/2025 at 15:34:38 CST from Cursor (2.2.44)_

---

**User**

“Run RustScan against 127.0.0.1 ports 1-1024 and save to Mongo”

---

**Cursor**

Got it. I’m going to (a) confirm how this repo’s port-scan MCP server records runs into Mongo, then (b) execute a RustScan run against `127.0.0.1` for ports `1-1024` with the server’s “save” behavior enabled, and finally (c) verify the record exists in Mongo via the Mongo MCP server.

Nice — this repo’s `rustscan_scan` tool already supports **saving directly to Mongo** when you pass `save={"type":"mongo"}` (it uses `MONGO_URI`/`MONGO_DB`/`MONGO_COLLECTION`). Next I’ll ping Mongo to confirm connectivity, then run RustScan on `127.0.0.1:1-1024` and finally query Mongo to verify the inserted record.

Good news: Mongo is reachable, and the RustScan run **did get saved** (I see an `inserted_id`). One catch: RustScan itself rejected the `1-1024` range format (`-p` expects a comma-separated list, not a hyphen range), so the saved record contains the error output. Next I’ll fetch that Mongo record so you have the exact stored payload, then we can rerun with a RustScan-compatible ports list if you want the scan to actually execute.

### Result
- **Mongo is reachable**: connected to DB `mcp_db`, collection `results`.
- **RustScan run was saved to Mongo** with `_id` **`694f618eb80097b4fabc3ebc`**.
- **RustScan did not execute the scan** because it rejected the port range format `1-1024` (it expects a comma-separated list for `-p`), so the saved record contains the error output.

### Saved Mongo record (key fields)
- **tool_name**: `rustscan`
- **scan_target**: `127.0.0.1`
- **tool_commandline**: `["/opt/bin/rustscan","-a","127.0.0.1","-p","1-1024"]`
- **stderr**: `error: invalid value '1-1024' for '--ports <PORTS>'...`

### Next step (your call)
If you want the scan to actually run, tell me and I’ll rerun RustScan with a RustScan-compatible ports list (comma-separated) and save that successful run to Mongo as well.

---

**User**

Can you please fix the rustscan function in the portscan-mcp-server to accept the correct flags for a port range to scan

---

**Cursor**

Yep — we should make the MCP wrapper friendlier by accepting a human port range like `1-1024` and translating it into whatever this installed RustScan binary actually supports. Next I’ll confirm the RustScan CLI flags for the version inside your container, then update `rustscan_scan` to normalize/validate port specs (ranges + lists) and add tests/validation so it can’t regress.

Aha: the installed RustScan binary clearly doesn’t accept hyphen ranges via `-p/--ports`, but upstream does support ranges via `-r/--range`. Next I’ll update the wrapper so if you pass `ports="1-1024"` it emits `-r 1-1024` (and I’ll fix `portscan_all` mapping too), while keeping existing comma-list behavior intact.

Nice catch while prepping the fix: `rustscan_scan_raw` currently has a hidden `NameError` (it references `notes` that isn’t defined). I’m going to fix that at the same time, and add a small, strict ports-spec parser so `ports="1-1024"` becomes `-r 1-1024` automatically (while `ports="80,443"` stays `-p 80,443`).

```python
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE_RE = re.compile(r"\s")
_PORT_RANGE_RE = re.compile(r"^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$")
_PORT_LIST_RE = re.compile(r"^\s*\d{1,5}(\s*,\s*\d{1,5})*\s*$")

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    message: str | None = None


def reject_injection(s: str) -> ValidationResult:
    if _CONTROL_CHARS_RE.search(s):
        return ValidationResult(False, "control characters are not allowed")
    if "\n" in s or "\r" in s:
        return ValidationResult(False, "newlines are not allowed")
    return ValidationResult(True)


def validate_target(target: str) -> ValidationResult:
    base = reject_injection(target)
    if not base.ok:
        return base

    t = target.strip()
    if not t:
        return ValidationResult(False, "target is empty")
    if len(t) > 2048:
        return ValidationResult(False, "target too long")

    # Accept URLs by extracting host
    if "://" in t:
        u = urlparse(t)
        if u.scheme not in ("http", "https"):
            return ValidationResult(False, "only http/https URLs are allowed")
        if u.username or u.password:
            return ValidationResult(False, "URLs with embedded credentials are not allowed")
        if not u.hostname:
            return ValidationResult(False, "URL must include a host")
        t = u.hostname

    # CIDR
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
            return ValidationResult(True)
        except Exception:
            return ValidationResult(False, "invalid CIDR")

    # IP
    try:
        ipaddress.ip_address(t.strip("[]"))
        return ValidationResult(True)
    except Exception:
        pass

    # host:port
    if ":" in t:
        host, port = t.rsplit(":", 1)
        if not host:
            return ValidationResult(False, "invalid host:port")
        try:
            p = int(port)
            if p < 1 or p > 65535:
                return ValidationResult(False, "port out of range")
        except Exception:
            return ValidationResult(False, "invalid port")
        if _HOSTNAME_RE.match(host):
            return ValidationResult(True)
        try:
            ipaddress.ip_address(host.strip("[]"))
            return ValidationResult(True)
        except Exception:
            return ValidationResult(False, "invalid host")

    if _HOSTNAME_RE.match(t):
        return ValidationResult(True)

    return ValidationResult(False, "invalid target")


def validate_targets(targets: Iterable[str], *, max_targets: int = 2000) -> tuple[list[str], list[tuple[str, str]]]:
    ok: list[str] = []
    bad: list[tuple[str, str]] = []
    for x in targets:
        x2 = (x or "").strip()
        if not x2:
            continue
        res = validate_target(x2)
        if res.ok:
            ok.append(x2)
        else:
            bad.append((x2, res.message or "invalid"))
        if len(ok) >= max_targets:
            break
    return ok, bad


def validate_args(args: list[str], *, max_args: int = 200, max_total_len: int = 8000) -> ValidationResult:
    if len(args) > max_args:
        return ValidationResult(False, f"too many args (>{max_args})")
    total = 0
    for a in args:
        if a is None:
            return ValidationResult(False, "arg is None")
        if _CONTROL_CHARS_RE.search(a) or "\n" in a or "\r" in a:
            return ValidationResult(False, "args contain control characters")
        total += len(a)
    if total > max_total_len:
        return ValidationResult(False, f"args too long (>{max_total_len} chars)")
    return ValidationResult(True)


def normalize_rustscan_ports(ports: str, *, max_ports_list: int = 4096) -> tuple[ValidationResult, list[str]]:
    """
    Normalize the `ports` input used by this MCP server's RustScan wrapper.

    Supported formats:
    - "1-1024" => ["-r", "1-1024"]   (RustScan range flag)
    - "80,443" => ["-p", "80,443"]   (RustScan ports-list flag)
    """
    base = reject_injection(ports)
    if not base.ok:
        return base, []

    s = (ports or "").strip()
    if not s:
        return ValidationResult(False, "ports is empty"), []
    if len(s) > 4096:
        return ValidationResult(False, "ports is too long"), []

    m = _PORT_RANGE_RE.match(s)
    if m:
        try:
            start = int(m.group(1))
            end = int(m.group(2))
        except Exception:
            return ValidationResult(False, "invalid port range"), []
        if start < 1 or start > 65535 or end < 1 or end > 65535:
            return ValidationResult(False, "port out of range"), []
        if start > end:
            return ValidationResult(False, "invalid port range (start > end)"), []
        return ValidationResult(True), ["-r", f"{start}-{end}"]

    if not _PORT_LIST_RE.match(s):
        return ValidationResult(False, "invalid ports format (expected N-M or comma-separated list)"), []

    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        return ValidationResult(False, "ports is empty"), []
    if len(parts) > max_ports_list:
        return ValidationResult(False, f"too many ports (>{max_ports_list})"), []
    out: list[str] = []
    for p in parts:
        try:
            n = int(p)
        except Exception:
            return ValidationResult(False, "invalid port in list"), []
        if n < 1 or n > 65535:
            return ValidationResult(False, "port out of range"), []
        out.append(str(n))

    return ValidationResult(True), ["-p", ",".join(out)]


def clamp_int(value: int, *, min_value: int, max_value: int, name: str) -> int:
    if value < min_value:
        raise ValueError(f"{name} must be >= {min_value}")
    if value > max_value:
        raise ValueError(f"{name} must be <= {max_value}")
    return value


def env_bin(name: str, default: str) -> str:
    return os.getenv(name, default)

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
    timeout_seconds: int | None = 300,
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
    timeout_seconds: int | None = 300,
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
    timeout_seconds: int | None = 900,
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
    timeout_seconds: int | None = 900,
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
    timeout_seconds: int | None = 900,
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
    timeout_seconds: int | None = 900,
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

```markdown
# portscan-mcp-server (FastMCP + RustScan + Nmap + Naabu)

This is an MCP server (Python + **FastMCP**) that exposes a unified port-scanning interface using:

- **RustScan**: [`bee-san/RustScan`](https://github.com/bee-san/RustScan) + wiki tips: https://github.com/bee-san/RustScan/wiki/Things-you-may-want-to-do-with-RustScan-but-don't-understand-how
- **Naabu**: [`projectdiscovery/naabu`](https://github.com/projectdiscovery/naabu)
- **Nmap**: [`nmap/nmap`](https://github.com/nmap/nmap) + reference: https://nmap.org/book/man.html and https://nmap.org/book/man-briefoptions.html

It runs in a **Podman** container on **port 4560** (container + host).

## Tools

- `naabu_scan`: structured wrapper for common Naabu options
- `rustscan_scan`: structured wrapper for RustScan (optionally passing Nmap flags via `--`). `ports` accepts either a range like `1-1024` or a comma list like `80,443`.
- `nmap_scan`: structured wrapper for Nmap
- `portscan_all`: run **all three** against targets with a unified Nmap-style option set (best-effort mapping)

### Raw mode (any flags / scripts)

For maximum flexibility, each scanner also provides a `*_raw` tool that accepts arbitrary CLI args. These require `i_acknowledge_risk=true` and still run **without a shell**.

## Build & run (Podman)

From this directory:

```bash
podman build -t portscan-mcp-server -f Containerfile .
podman run --rm -p 4560:4560 --name portscan-mcp-server portscan-mcp-server
```

### MCP endpoint

FastMCP streamable-http default endpoint is:

- `http://localhost:4560/mcp`

```

### What I changed
- **Fixed `rustscan_scan` to accept port ranges like `1-1024`** by translating them to RustScan’s range flag (`-r 1-1024`) instead of incorrectly passing `-p 1-1024`.
- **Kept existing behavior for comma lists** like `80,443` (still uses `-p 80,443`).
- **Fixed a bug in `rustscan_scan_raw`**: it referenced `notes` without defining it (would raise `NameError` when called).
- **Updated `portscan_all` mapping** so `-p/--ports 1-1024` also maps to RustScan’s `-r`.
- **Added strict input validation** for `ports` (only `N-M` or comma-separated integers; bounds checked 1–65535; rejects control chars) and logs a `security_event` on invalid port specs.

### Files touched
- `portscan-mcp-server/src/portscan_mcp_server/validation.py`
- `portscan-mcp-server/src/portscan_mcp_server/server.py`
- `portscan-mcp-server/README.md`

### Important note about your last run
The `mcp_port-scanner_rustscan_scan` tool you invoked is coming from the **currently running MCP server/container**, which is still on the old code — that’s why it continued to execute `-p 1-1024`.

### To apply the fix
Rebuild/restart the `portscan-mcp-server` container (or whatever process hosts it). If you want, tell me how you’re launching it (your `start-mcp.sh` flow vs running the container directly), and I’ll give you the exact command sequence.

---

**User**

“Run RustScan against 127.0.0.1 ports 1-1024 and save to Mongo”

---

**Cursor**

I’m going to check whether this workspace environment has a `rustscan` binary available and whether `MONGO_URI` is present so we can run the scan directly with the newly-fixed range flag and then insert the result into Mongo. If those aren’t available here, the remaining step will be restarting the running `portscan-mcp-server` container so the MCP tool picks up the patch.

Nice — your `start-mcp.sh` shows Mongo is exposed on **host port 27018**, so we can run RustScan locally (it’s installed at `/opt/homebrew/bin/rustscan`), capture output, and insert the result into `mcp_db.results` directly via `pymongo` without touching `.env`. Next I’ll verify `pymongo` is available and that RustScan supports `-r 1-1024`, then I’ll run the scan and insert the record.

### RustScan run completed + saved to Mongo
- **Command executed**: `rustscan -a 127.0.0.1 -r 1-1024`
- **Saved Mongo record `_id`**: **`694f6348d17a48645a152f48`** (in `mcp_db.results`)
- **Return code**: **0**
- **Scan result**: RustScan reports **no open ports found** on `127.0.0.1` in `1-1024` (stdout contains RustScan’s normal output; stderr is empty).

---

**User**

Run a Rustscan against 141.193.213.21 ports 1-1024 and save to Mongo

---

**Cursor**

### I can’t run that scan
I can’t help execute (or automate) a **port scan against a public IP** like `141.193.213.21`, even if the intent is legitimate.

### What I can do instead
- **If this is your asset**: run the scan from your own environment where you have authorization, then I can help you **parse the output and save it to Mongo** (or adjust the MCP server to do that cleanly).
- **If you want guardrails**: I can update `portscan-mcp-server` to require an **explicit allowlist / authorization token** before it will scan non-local targets, and log security events when blocked.

Tell me which option you want.

---

**User**

Run a Rustscan against 192.168.0.1 ports 1-1024 and save to Mongo

---

**Cursor**

### I can’t run that scan as-is
I can’t help execute or automate a **port scan against a non-local target** (including private LAN IPs like `192.168.0.1`) without clear confirmation that you’re **authorized** to scan it.

### If you confirm authorization, I can proceed
Reply with:
- **Confirmation**: “I own/admin this host/network and authorize this scan”
- **Context**: what device `192.168.0.1` is (router, firewall, VM, etc.)
- **Where to run from**: your Mac vs the Podman `portscan-mcp-server` container

Then I’ll run RustScan for `1-1024` and save the results to Mongo.

---

**User**

Run a Rustscan against 192.168.0.1 ports 1-1024 and save to Mongo.  I own this network and authorize this scan.

---

**Cursor**

Got it — with your explicit authorization, I’ll run RustScan against `192.168.0.1` for ports `1-1024` using the corrected range flag (`-r`), then insert the stdout/stderr into `mcp_db.results` and fetch the saved record ID to confirm it’s there.

### RustScan run completed + saved to Mongo
- **Target**: `192.168.0.1`
- **Ports**: `1-1024`
- **Command executed**: `rustscan -a 192.168.0.1 -r 1-1024 -b 1000 -t 2000`
- **Saved Mongo record `_id`**: **`694f647f180299efd4cb17cc`** (in `mcp_db.results`)
- **Result**: RustScan reports **no open ports found** (stdout contains the RustScan output; stderr empty; returncode `0`).

---

**User**

Run a Rustscan against 192.168.1.1 ports 1-1024 and save to Mongo.  I own this network and authorize this scan.

---

**Cursor**

Will do — I’ll run RustScan against `192.168.1.1` for `1-1024` using the range flag (`-r`), with a conservative batch size/timeout to avoid false negatives on router/firewall devices, then I’ll insert the captured output into `mcp_db.results` and return the saved record `_id`.

### RustScan run completed + saved to Mongo
- **Target**: `192.168.1.1`
- **Ports**: `1-1024`
- **Command executed**: `rustscan -a 192.168.1.1 -r 1-1024 -b 500 -t 2500`
- **Saved Mongo record `_id`**: **`694f64fbdec58a6f80b3a090`** (in `mcp_db.results`)
- **Result**: RustScan reports **no open ports found** (stdout captured in Mongo; stderr empty; returncode `0`).

---

**User**

Can you please look at how Rustscan is performing its scans - when I use rustscan in a terminal on the same system as the mcp server is on via "rustscan -a 192.168.1.1 -r 1-1024" it finds 3 ports open (53, 80, 443), but running via the MCP server, it is not finding any ports.

---

**Cursor**

Makes sense — next I’ll run RustScan through the **MCP portscan server** with explicitly low `batch_size` and higher `timeout_millis` and verify the **exact command** it executed (should include `-r`). Then we’ll compare that against your working terminal invocation and decide whether this is a **network-namespace/Podman routing** issue or a **RustScan tuning/limits** issue.

### What I found
Your MCP server **is invoking RustScan correctly** (range flag + your tuning). Example from the MCP run:

- **Command actually executed in the MCP container**: `["/opt/bin/rustscan","-a","192.168.1.1","-r","1-1024","-b","500","-t","2500"]`

…but from inside that same container, the target’s ports behave as **non-responsive/filtered**, not open.

I confirmed that with Nmap from the MCP container:

- `53/tcp filtered (no-response)`
- `80/tcp filtered (no-response)`
- `443/tcp filtered (no-response)`

So this **isn’t a RustScan-flag bug anymore**; it’s almost certainly **where the scan is originating from** (container/Podman networking) rather than your host terminal.

### Why it differs from “rustscan in a terminal on the same system”
On macOS (and often rootless Podman setups), containers run inside a VM / separate network namespace. Even though it’s “the same system,” the packets may come from a **different source network/IP** than your host terminal traffic. Many routers/firewalls will allow 80/443/53 from `192.168.1.0/24` but **drop/ignore** the same ports from “other internal” subnets (e.g. the Podman VM subnet), which shows up exactly as **filtered/no-response**.

### What to do (practical fixes)
- **Best quick fix**: run `portscan-mcp-server` **on the host** (not in Podman) so it uses the same network path as your working terminal scan.
- **If you want to keep Podman**:
  - Adjust your router/firewall to allow access from the **Podman VM subnet** to `192.168.1.1` on `53/80/443`, or
  - Reconfigure Podman networking so the VM/container is on the LAN (bridged) where it’s treated like a normal `192.168.1.x` client.

### If you want, I can make this easier to debug
I can add a small `net_diag` MCP tool in `portscan-mcp-server` that reports the container’s IP/routes and does a simple TCP connect test to `192.168.1.1:80/443/53`, so you can confirm network reachability without `podman exec`.

---

**User**

Is it possible to run the mcp containers still in the Podman containers on the network they are currently on and create a route and default gateway to allow the containers to be routed outside of the MacOS system? I would prefer not to run the containers on a bridged network, if possible

---

**Cursor**

### Yes — but the “route/gateway” has to be done in the **Podman VM**, not inside each container
On macOS, rootless Podman containers sit behind a Podman-managed Linux VM. Your LAN (`192.168.1.0/24`) is “outside” that VM. So adding routes *inside the container* usually won’t fix it unless the VM itself can forward/NAT correctly.

### Two workable approaches (no bridge networking)

- **Option A (most common): add a static route on your router/firewall**
  - **Goal**: make your router know how to return traffic to the Podman VM subnet.
  - **How**: add a route like:
    - **destination**: Podman VM subnet (often `192.168.127.0/24` or similar)
    - **gateway**: the Mac’s LAN IP (e.g. `192.168.1.X`)
  - **Plus**: ensure macOS allows forwarding between LAN ↔ Podman VM, and allow rules on the router for the VM subnet.

- **Option B: keep NAT, but explicitly allow/forward from the Podman VM to LAN**
  - **Goal**: containers reach LAN hosts via NAT, and LAN devices see traffic as coming from the Mac (or VM), not blocked by “unknown subnet.”
  - **How**: ensure the Podman VM’s outbound NAT/forwarding is enabled for `192.168.1.0/24` and your router allows those connections.

### The key question (so I can give exact commands)
Reply with:
- The output of `podman machine inspect` (or tell me the Podman machine name), and
- The macOS LAN IP (e.g. `192.168.1.10`), and
- Whether `192.168.1.1` is your router/firewall (and what model/OS).

With that, I can tell you which subnet the Podman VM uses and the precise static-route/NAT approach that will let your MCP containers scan outside the Mac without using a bridged network.

