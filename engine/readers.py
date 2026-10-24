#!/usr/bin/env python3
"""exposure-scan : lecteurs locaux (LECTURE SEULE, aucun réseau).

Chaque lecteur reçoit des OCTETS (jamais un chemin) et ne renvoie que des champs d'une liste blanche :
- appel  : horodatage(s), client, nom de serveur côté client, nom d'outil, + provenance (source, ligne, empreintes opaques) ;
- définition présentée : client, serveur, outil, empreinte(s) par algorithme du journal signé, heure locale ;
- audit du proxy : at, server_id, event, live_tools_sha256.
Arguments, contenu de réponse, prompt, texte de message, description d'outil : jamais copiés. Les définitions d'outil
sont réduites à leur empreinte SHA-256 dès la lecture. Les identifiants internes (tool_use id, session) sont remplacés
par un SHA-256 tronqué.

discover() trouve les sources (find), extract() les lit via une fonction read_fn(source) -> octets ; build.py lit les
fichiers vivants, verify.py --sources relit le même PRÉFIXE (fichiers append-only) et exige le même résultat."""
import hashlib, json, os, re, glob, time
from datetime import datetime, timezone

_H = os.path.dirname(os.path.abspath(__file__))
import sys  # noqa: E402
for _p in (_H, os.path.join(_H, "vendor")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import verify_tlog as VT  # noqa: E402

ALGOS = ("sha256(canon(sorted[{name,description,inputSchema}]))/v1", "sha256(JCS-RFC8785(sorted[{name,description,inputSchema}]))/v2")
CALL_KEYS = {"id", "client", "server_name", "tool", "at_lo", "at_hi", "at_source", "source", "line", "call_ref", "session_ref",
             "time_sources", "time_status", "duplicates"}
DEF_KEYS = {"id", "client", "server_name", "tool", "per_tool_sha256", "at", "at_source", "source", "line", "session_ref"}
AUDIT_KEYS = {"id", "at", "server_id", "event", "live_tools_sha256", "source", "line"}
CC_PREFIX = re.compile(r"^mcp__(.+?)__(.+)$")
LOG_RE = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) \[info\] \[agentTranslation\] mcpToolCall bubble: serverName="([^"]+)", toolName="([^"]+)"')


def ref(s):
    return hashlib.sha256(str(s).encode()).hexdigest()[:16]


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def tool_hashes(name, description, schema):
    t = {"name": name, "description": description, "inputSchema": schema}
    t = {k: v for k, v in t.items() if v is not None}
    return {a: hashlib.sha256(VT.canon_fp_for(a)(t)).hexdigest() for a in ALGOS}


def _lines(data):
    for n, l in enumerate(data.split(b"\n")):
        if l.strip():
            yield n, l


# ---------- Claude Code ----------
def read_claude(data, sid):
    """Appels mcp__* (tool_use) et définitions mcp__* (api-request-shape) d'une transcription Claude Code."""
    calls, defs, results = [], [], {}
    for n, l in _lines(data):
        if b"mcp__" not in l and b"tool_result" not in l:
            continue
        try:
            o = json.loads(l)
        except ValueError:
            continue
        if o.get("type") == "api-request-shape":
            for t in (o.get("shape") or {}).get("tools") or []:
                m = CC_PREFIX.match(str(t.get("name", "")))
                if m:
                    defs.append({"client": "claude-code", "server_name": m.group(1), "tool": m.group(2),
                                 "per_tool_sha256": tool_hashes(m.group(2), t.get("description"), t.get("input_schema")),
                                 "at": o.get("timestamp"), "at_source": "timestamp de l'entrée api-request-shape (local, non signé)",
                                 "source": sid, "line": n, "session_ref": ref(o.get("sessionId"))})
            continue
        msg = o.get("message") if isinstance(o.get("message"), dict) else {}
        content = msg.get("content") if isinstance(msg.get("content"), list) else []
        for c in content:
            if not isinstance(c, dict):
                continue
            if c.get("type") == "tool_use":
                m = CC_PREFIX.match(str(c.get("name", "")))
                if m:
                    calls.append({"client": "claude-code", "server_name": m.group(1), "tool": m.group(2), "at_lo": o.get("timestamp"),
                                  "source": sid, "line": n, "call_ref": ref(c.get("id")), "session_ref": ref(o.get("sessionId"))})
            elif c.get("type") == "tool_result":
                results.setdefault(ref(c.get("tool_use_id")), o.get("timestamp"))
    for c in calls:
        c["at_hi"] = results.get(c["call_ref"])
        c["at_source"] = "tool_use.timestamp → tool_result.timestamp de la transcription (local, non signé)"
    return calls, defs


# ---------- Cursor ----------
def read_cursor_transcript(data, sid):
    """Appels MCP (CallMcpTool / call_mcp_tool) d'une transcription Cursor. La transcription ne porte pas d'heure."""
    calls = []
    for n, l in _lines(data):
        try:
            o = json.loads(l)
        except ValueError:
            continue
        for k, c in enumerate((o.get("message") or {}).get("content") or []):
            inp = c.get("input") if isinstance(c, dict) and isinstance(c.get("input"), dict) else {}
            if c.get("type") == "tool_use" and "toolName" in inp and "server" in inp:
                calls.append({"client": "cursor", "server_name": str(inp["server"]), "tool": str(inp["toolName"]), "source": sid, "line": n,
                              "call_ref": ref("%s:%d:%d" % (sid, n, k)), "session_ref": ref(sid)})
    return calls


def read_cursor_log(data, mtime_ns):
    """Lignes « mcpToolCall bubble » (heure locale) -> UTC. Décalage = fuseau système à cet instant, contrôlé contre le
    mtime du fichier (dernière ligne horodatée vs mtime, tolérance 120 s) ; incohérent -> offset_ok False."""
    ev, last = [], None
    for _, l in _lines(data):
        s = l.decode("utf-8", "replace")
        m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) ", s)
        if m:
            last = m.group(1)
        m = LOG_RE.match(s)
        if m:
            ev.append((m.group(1), m.group(2), m.group(3)))
    if last is None:
        return [], {"offset_ok": False, "why": "aucune ligne horodatée"}
    naive = datetime.strptime(last, "%Y-%m-%d %H:%M:%S.%f")
    off = time.localtime(mtime_ns / 1e9).tm_gmtoff
    last_utc = naive.replace(tzinfo=timezone.utc).timestamp() - off
    ok = abs(last_utc - mtime_ns / 1e9) <= 120
    out = [{"at": iso(datetime.fromtimestamp(datetime.strptime(t, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp() - off, timezone.utc)),
            "server_name": sname, "tool": tool} for t, sname, tool in ev]
    return out, {"offset_ok": ok, "utc_offset_s": off, "check": "dernière ligne locale %s - décalage %+d s vs mtime %s : écart %.3f s"
                 % (last, off, iso(datetime.fromtimestamp(mtime_ns / 1e9, timezone.utc)), last_utc - mtime_ns / 1e9)}


def read_cursor_tool(data, sid, mtime_ns, server_name):
    d = json.loads(data)
    return {"client": "cursor", "server_name": server_name, "tool": d["name"],
            "per_tool_sha256": tool_hashes(d["name"], d.get("description"), d.get("arguments")),
            "at": iso(datetime.fromtimestamp(mtime_ns / 1e9, timezone.utc)), "at_source": "mtime du fichier écrit par Cursor (local, modifiable)",
            "source": sid, "line": 0, "session_ref": None}


# ---------- proxy legion-guard ----------
def read_audit(data, sid):
    out = []
    for n, l in _lines(data):
        o = json.loads(l)
        out.append({"at": o.get("at"), "server_id": o.get("server_id"), "event": o.get("event"),
                    "live_tools_sha256": o.get("live_tools_sha256"), "source": sid, "line": n})
    return out


# ---------- configuration (correspondance nom client -> server_id) ----------
def _server_id_of(entry):
    a = [str(x) for x in (entry.get("args") or [])]
    return a[a.index("--server-id") + 1] if "--server-id" in a and a.index("--server-id") + 1 < len(a) else None


def read_config(data, client):
    d = json.loads(data)
    servers = []
    for k, v in (d.get("mcpServers") or {}).items():
        servers.append((k, v))
    for pv in (d.get("projects") or {}).values():
        for k, v in (pv.get("mcpServers") or {}).items():
            servers.append((k, v))
    out = {}
    for k, v in servers:
        if not isinstance(v, dict):
            continue
        name = ("user-" + k) if client == "cursor" else k
        out.setdefault(name, set()).add(_server_id_of(v))
    return {k: sorted(x or "<sans --server-id>" for x in v) for k, v in out.items()}


# ---------- découverte + extraction ----------
def discover(home, since_ts):
    """Sources candidates (find). Les transcriptions dont le dernier mtime précède since_ts sont listées comme exclues."""
    S, excluded = [], []
    for p in sorted(glob.glob(os.path.join(home, ".claude", "projects", "**", "*.jsonl"), recursive=True)):
        (S if os.stat(p).st_mtime >= since_ts else excluded).append({"kind": "claude_transcript", "path": p})
    for p in sorted(glob.glob(os.path.join(home, ".cursor", "projects", "*", "agent-transcripts", "**", "*.jsonl"), recursive=True)):
        (S if os.stat(p).st_mtime >= since_ts else excluded).append({"kind": "cursor_transcript", "path": p})
    for p in sorted(glob.glob(os.path.join(home, ".config", "Cursor", "logs", "*", "window*", "workbench.mcp.allowlist.log"))):
        if os.stat(p).st_mtime >= since_ts:
            S.append({"kind": "cursor_log", "path": p})
    for d in sorted(glob.glob(os.path.join(home, ".cursor", "projects", "*", "mcps", "*", "tools"))):
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if f.endswith(".json") and os.stat(p).st_mtime >= since_ts:
                S.append({"kind": "cursor_tool", "path": p, "server_name": os.path.basename(os.path.dirname(d))})
    snap = os.path.join(home, "legion-control-plane", "packages", "change-exposure-20261024", "cases", "dexpaprika-cursor-20261024-src",
                        "artifacts", "cursor", "tools")
    if os.path.isdir(snap):  # copie (shutil.copy2, mtime préservé) du stockage Cursor faite avant sa réécriture de 02:49Z
        for f in sorted(os.listdir(snap)):
            S.append({"kind": "cursor_tool", "path": os.path.join(snap, f), "server_name": "user-dexpaprika-guarded",
                      "note": "instantané conservé par change-exposure-20261024 (copy2, mtime d'origine)"})
    for p, k in ((os.path.join(home, ".cache", "legion-guard", "proxy-audit.jsonl"), "proxy_audit"),
                 (os.path.join(home, ".claude.json"), "claude_config"), (os.path.join(home, ".cursor", "mcp.json"), "cursor_config")):
        if os.path.exists(p):
            S.append({"kind": k, "path": p})
    return S, excluded


def extract(sources, read_fn, since, cutoff):
    """sources : liste ordonnée (id = index). read_fn(src) -> (octets, mtime_ns). Résultat déterministe."""
    calls, defs, audit, mapping, cur_calls, logs = [], [], [], {"claude-code": {}, "cursor": {}}, [], []
    for i, s in enumerate(sources):
        sid = "S%03d" % i
        data, mt = read_fn(s)
        k = s["kind"]
        if k == "claude_transcript":
            c, d = read_claude(data, sid)
            calls += c; defs += d
        elif k == "cursor_transcript":
            cur_calls += read_cursor_transcript(data, sid)
        elif k == "cursor_log":
            ev, chk = read_cursor_log(data, mt)
            logs.append((sid, ev, chk))
        elif k == "cursor_tool":
            d = read_cursor_tool(data, sid, mt, s["server_name"])
            defs.append(d)
        elif k == "proxy_audit":
            audit += read_audit(data, sid)
        elif k == "claude_config":
            mapping["claude-code"].update(read_config(data, "claude-code"))
        elif k == "cursor_config":
            mapping["cursor"].update(read_config(data, "cursor"))
    # Heure des appels Cursor : déduite du journal Cursor (même serveur, même outil). Rattachement accepté seulement si
    # la transcription contient exactement 1 appel (serveur, outil) et que les lignes du journal pour ce couple forment
    # un seul groupe de moins de 60 s ; sinon heure UNKNOWN.
    for c in cur_calls:
        short = c["server_name"][5:] if c["server_name"].startswith("user-") else c["server_name"]
        same = [x for x in cur_calls if x["server_name"] == c["server_name"] and x["tool"] == c["tool"]]
        hits = [(sid, e) for sid, ev, chk in logs if chk["offset_ok"] for e in ev if e["server_name"] == short and e["tool"] == c["tool"]]
        bad = [sid for sid, ev, chk in logs if not chk["offset_ok"] and any(e["server_name"] == short and e["tool"] == c["tool"] for e in ev)]
        c["time_sources"] = sorted({sid for sid, _ in hits})
        if len(same) == 1 and hits and not bad and (ts(max(e["at"] for _, e in hits)) - ts(min(e["at"] for _, e in hits))).total_seconds() < 60:
            c["at_lo"], c["at_hi"] = min(e["at"] for _, e in hits), max(e["at"] for _, e in hits)
            c["at_source"] = ("DÉDUCTION : lignes « mcpToolCall bubble » du journal Cursor (%s) pour ce serveur et cet outil, heure locale "
                              "convertie en UTC ; rattachement à la transcription par (serveur, outil), unique" % ",".join(c["time_sources"]))
        else:
            c["at_lo"] = c["at_hi"] = None
            c["at_source"] = "UNKNOWN : rattachement transcription ↔ journal Cursor non univoque (%d appels, %d lignes, %d journaux au décalage incohérent)" % (len(same), len(hits), len(bad))
        calls.append(c)
    # Dédoublonnage Claude Code (une session reprise recopie l'historique) : même call_ref = même appel.
    seen, uniq = {}, []
    for c in calls:
        key = (c["client"], c["call_ref"])
        if key in seen:
            seen[key].setdefault("duplicates", []).append("%s:%d" % (c["source"], c["line"]))
            continue
        seen[key] = c; uniq.append(c)
    s0, s1 = ts(since), ts(cutoff)
    kept, before = [], 0
    for c in uniq:
        c["time_status"] = "OK"
        if c["at_lo"] is None:
            c["time_status"] = "UNKNOWN"
        else:
            lo, hi = ts(c["at_lo"]), ts(c["at_hi"]) if c.get("at_hi") else None
            if hi is not None and hi < lo:
                c["time_status"] = "INCOHERENT (fin avant début)"
            elif lo > s1:
                c["time_status"] = "INCOHERENT (postérieur à l'extraction)"
            if c["at_hi"] is None:
                c["at_hi"] = c["at_lo"]
                c["at_source"] += " ; fin absente (pas de tool_result) : instant ponctuel"
            if hi is not None and hi < s0 or (hi is None and lo < s0):
                before += 1
                continue
        kept.append(c)
    for n, c in enumerate(sorted(kept, key=lambda c: (c["at_lo"] or "9", c["client"], c["call_ref"]))):
        c["id"] = "CALL-%03d" % n
    for n, d in enumerate(defs):
        d["id"] = "DEF-%04d" % n
    for n, a in enumerate(audit):
        a["id"] = "AUD-%03d" % n
    kept.sort(key=lambda c: c["id"])
    return {"calls": kept, "defs": defs, "audit": audit, "mapping": mapping,
            "cursor_logs": [{"source": sid, "events": len(ev), **chk} for sid, ev, chk in logs],
            "calls_before_since": before}
