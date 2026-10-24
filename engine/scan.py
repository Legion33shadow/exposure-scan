#!/usr/bin/env python3
"""exposure-scan : « pour chaque appel passé de mes agents, quelle version SIGNÉE de l'outil était en service ? »

derive(dossier_dir) est une fonction pure de dossier_dir/inputs.json et des artefacts qu'il référence (aucun réseau,
aucune lecture hors du dossier). Les vérifications du journal signé et de la couverture signée sont celles du moteur
change-exposure-20261024 (vendor/exposure.py, copie non modifiée : verify_signed_log, verify_coverage, change_windows).

Étiquettes :
- FAIT      : une définition présentée par un client a une empreinte identique à une empreinte signée (feuille N) ;
              une signature / une inclusion RFC 6962 / une couverture signée vérifiées ici.
- DÉDUCTION : position d'un appel par rapport à une fenêtre de changement ; version « encadrée » par deux observations
              signées identiques (un aller-retour non observé entre elles n'est pas exclu).
- UNKNOWN   : aucune feuille reliable, horodatage absent/incohérent, appel hors de toute observation signée. Jamais 0.
Toute relation de provenance invalide lève InvalidCase : aucun résultat n'est produit."""
import json, os, sys
from datetime import datetime, timezone

_H = os.path.dirname(os.path.abspath(__file__))
for _p in (_H, os.path.join(_H, "vendor")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import exposure as E  # noqa: E402  moteur change-exposure (copie non modifiée)
from readers import CALL_KEYS, DEF_KEYS, AUDIT_KEYS  # noqa: E402

SCHEMA_IN = "legion-exposure-scan/0.1"
SCHEMA_OUT = "legion-exposure-scan-result/0.1"
InvalidCase = E.InvalidCase
FORBIDDEN = {"arguments", "input", "content", "text", "result", "prompt", "message", "description", "inputSchema", "input_schema", "output"}
LIMITS = [
    "Seuls le journal signé (feuilles, tête, inclusion) et la couverture signée sont vérifiés cryptographiquement. "
    "Transcriptions, journaux clients, caches de définitions, audit du proxy, configurations et mtimes sont locaux, non signés, modifiables.",
    "La position d'un appel par rapport à une fenêtre de changement est une DÉDUCTION : l'heure exacte d'un changement est inconnue, "
    "seule une fenêtre [dernière observation de l'ancienne version, première observation de la nouvelle] est connue.",
    "Une version « encadrée » par deux observations signées identiques n'exclut pas un aller-retour non observé entre les deux.",
    "Après la dernière observation signée du bundle (journal : tête 34964 ; couverture : tête 53), rien n'est signé : UNOBSERVED.",
    "La correspondance nom de serveur client → server_id vient de la configuration actuelle (--server-id) : elle peut différer "
    "de la configuration au moment de l'appel.",
    "Exhaustivité non prouvée : un appel absent des transcriptions locales (supprimée, autre machine, autre client) n'est pas vu.",
    "Aucun argument, contenu de réponse, prompt ni message n'est extrait : l'effet d'un appel est hors champ (IMPACT inconnu).",
]


def _ts(s):
    return E._ts(s)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _case(d, spec, server_id=None, shards=None):
    c = E.Case.__new__(E.Case)
    c.dir, c.arts = os.path.abspath(d), spec["artifacts"]
    c.spec = {"server_id": server_id, "artifacts": spec["artifacts"], "signed_log": spec["signed_log"]}
    if shards is not None:
        cv = dict(spec["coverage"]); cv["shards"] = shards
        c.spec["coverage"] = cv
    return c


def _check_keys(rows, allowed, what):
    for r in rows:
        bad = set(r) - allowed
        if bad or set(r) & FORBIDDEN:
            raise InvalidCase("%s %s : champs interdits ou inattendus %s" % (what, r.get("id"), sorted(bad | (set(r) & FORBIDDEN))))


def _leaf_tool_hash(rec, tool):
    return dict(rec["tools_fingerprint"]["per_tool_sha256"]).get(tool)


def timeline(sid, tool, leaves, states, since, cutoff):
    """Points d'observation signés (feuilles + cycles OBSERVED) puis segments entre points consécutifs."""
    by_fp = {}
    for r in leaves:
        by_fp.setdefault(r["tools_fingerprint"]["sha256"], r)
    pts, gaps = [], []
    for r in leaves:
        pts.append({"from": r["observed_at"], "to": r["observed_at"], "version": _leaf_tool_hash(r, tool) or "ABSENT",
                    "source": "feuille signée %d" % r["leaf_index"], "leaf": r["leaf_index"]})
    for s in states:
        if s["state"] == "OBSERVED":
            r = by_fp.get(s["fp"])
            pts.append({"from": s["slot_start"], "to": s["observed_by"], "leaf": r["leaf_index"] if r else None,
                        "version": (_leaf_tool_hash(r, tool) or "ABSENT") if r else "INCONNUE (empreinte globale sans feuille dans le bundle)",
                        "source": "couverture signée, cycle %d" % s["cycle"]})
        else:
            gaps.append({"from": s["slot_start"], "to": s["observed_by"] or s["slot_start"], "state": "UNOBSERVED",
                         "detail": "couverture signée cycle %d : %s%s" % (s["cycle"], s["state"], (" (%s)" % s["reason"]) if s["reason"] else "")})
    pts.sort(key=lambda p: (_ts(p["to"]), _ts(p["from"])))
    segs = []
    first = pts[0] if pts else None
    if first is None or _ts(first["from"]) > _ts(since):
        segs.append({"from": since, "to": first["from"] if first else cutoff, "state": "UNOBSERVED", "detail": "aucune observation signée antérieure"})
    for a, b in zip(pts, pts[1:]):
        lo, hi = sorted((a["to"], b["from"]), key=_ts)
        inner = [g for g in gaps if _ts(lo) <= _ts(g["from"]) and _ts(g["to"]) <= _ts(hi)]
        seg = {"from": lo, "to": hi, "bounds": [a["source"], b["source"]], "unobserved_inside": len(inner)}
        if _ts(b["from"]) < _ts(a["to"]):
            seg["overlap"] = "observations chevauchantes (créneau de couverture englobant l'autre observation) : aucun intervalle non couvert"
        if a["version"] == b["version"]:
            seg.update(state="STABLE_DEDUIT", version=a["version"])
        else:
            seg.update(state="CHANGEMENT", version_before=a["version"], version_after=b["version"])
        segs.append(seg)
    if pts:
        segs.append({"from": pts[-1]["to"], "to": cutoff, "state": "UNOBSERVED", "detail": "après la dernière observation signée du bundle",
                     "last_signed_version": pts[-1]["version"]})
    segs += gaps
    segs.sort(key=lambda s: (_ts(s["from"]), _ts(s["to"])))
    return {"server_id": sid, "tool": tool, "observations": pts, "segments": [s for s in segs if _ts(s["to"]) >= _ts(since) or s["state"] != "UNOBSERVED"]}


def version_at(tl, lo, hi):
    pts = tl["observations"]
    before = [p for p in pts if _ts(p["to"]) <= lo]
    after = [p for p in pts if _ts(p["from"]) >= hi]
    b = before[-1] if before else None
    a = min(after, key=lambda p: _ts(p["from"])) if after else None
    if b is None:
        return {"status": "UNKNOWN", "basis": "UNKNOWN", "why": "aucune observation signée antérieure à l'appel", "version": None}
    if a is None:
        return {"status": "UNOBSERVED", "basis": "UNKNOWN", "version": None, "last_signed_version": b["version"], "last_signed_at": b["to"],
                "why": "appel postérieur à la dernière observation signée (%s, %s) : version en service non signée" % (b["source"], b["to"])}
    if a["version"] == b["version"]:
        return {"status": "ENCADRE", "basis": "DÉDUCTION", "version": b["version"], "bounds": [b["source"], b["to"], a["source"], a["from"]],
                "why": "même version signée observée avant et après l'appel ; un aller-retour non observé n'est pas exclu"}
    return {"status": "DANS_UN_TROU", "basis": "DÉDUCTION", "version": None, "candidates": [b["version"], a["version"]],
            "bounds": [b["source"], b["to"], a["source"], a["from"]], "why": "la version change entre les deux observations signées qui encadrent l'appel"}


def classify(lo, hi, w):
    lower = _ts(w["lower_bound"]) if w.get("lower_bound") else None
    upper = _ts(w["upper_bound"])
    if lo > upper:
        return "APRÈS"
    if lower is not None and hi < lower:
        return "AVANT"
    if lower is None:
        return "UNKNOWN"
    return "DANS_UN_TROU"


def derive(d):
    p = os.path.join(d, "inputs.json")
    if not os.path.isfile(p):
        raise InvalidCase("inputs.json absent")
    spec = json.load(open(p, encoding="utf-8"))
    if spec.get("schema") != SCHEMA_IN:
        raise InvalidCase("schéma d'entrée inconnu : %r" % spec.get("schema"))
    base = _case(d, spec)
    log_report, recs, sth = E.verify_signed_log(base)
    ex = spec["extract"]
    calls, defs, audit = base.jsonl(ex["calls"], "calls"), base.jsonl(ex["defs"], "defs"), base.jsonl(ex["audit"], "audit")
    sources = base.json(ex["sources"], "sources")
    mapping = base.json(ex["mapping"], "mapping")
    _check_keys(calls, CALL_KEYS, "appel"); _check_keys(defs, DEF_KEYS, "définition"); _check_keys(audit, AUDIT_KEYS, "audit")
    sids = {s["id"] for s in sources}
    for r in calls + defs + audit:
        if r.get("source") not in sids:
            raise InvalidCase("%s : lien de provenance invalide (source %r inconnue)" % (r.get("id"), r.get("source")))
        for x in r.get("time_sources") or []:
            if x not in sids:
                raise InvalidCase("%s : source horaire %r inconnue" % (r.get("id"), x))
    since, cutoff = spec["since"], spec["cutoff"]
    for c in calls:
        for k in ("at_lo", "at_hi"):
            if c.get(k) is not None:
                try:
                    _ts(c[k])
                except ValueError:
                    raise InvalidCase("%s : horodatage illisible %r" % (c["id"], c[k]))
    servers = {}
    for sid, shards in sorted(spec["servers"].items()):
        cov_report, states = E.verify_coverage(_case(d, spec, sid, shards), sid)
        leaves = sorted((r for r in recs.values() if r["server_id"] == sid), key=lambda r: r["leaf_index"])
        if not leaves:
            raise InvalidCase("serveur %s déclaré sans feuille signée dans le dossier" % sid)
        for r in leaves:
            if r.get("prev_leaf_index") is not None and r["prev_leaf_index"] not in recs and _ts(r["observed_at"]) >= _ts(since):
                raise InvalidCase("feuille %d : feuille précédente %d absente du dossier" % (r["leaf_index"], r["prev_leaf_index"]))
        chs = [{"id": "LEAF-%d" % r["leaf_index"], "detail": {"change_kind": "tool_definition", "leaf_index": r["leaf_index"],
                                                             "prev_leaf_index": r.get("prev_leaf_index")}} for r in leaves]
        windows, gaps = E.change_windows(chs, recs, cov_report, states)
        for w, r in zip(windows, leaves):
            ch = r.get("change") or {}
            w["leaf_index"] = r["leaf_index"]
            w["tools_changed"] = sorted(set(ch.get("added", [])) | set(ch.get("modified", [])) | set(ch.get("removed", [])))
        tools = sorted({t for r in leaves for t in dict(r["tools_fingerprint"]["per_tool_sha256"])})
        servers[sid] = {"coverage": cov_report, "states": states, "leaves": leaves, "windows": windows, "gaps": gaps,
                        "timelines": {t: timeline(sid, t, leaves, states, since, cutoff) for t in tools}}
    # FAIT : définitions présentées dont l'empreinte = empreinte signée
    def sid_of(client, name):
        ids = (mapping.get(client) or {}).get(name)
        return ids[0] if ids and len(ids) == 1 and ids[0] in servers else None

    def_facts = []
    for df in defs:
        sid = sid_of(df["client"], df["server_name"])
        m = []
        if sid:
            for r in servers[sid]["leaves"]:
                h = _leaf_tool_hash(r, df["tool"])
                if h and df["per_tool_sha256"].get(r["tools_fingerprint"]["algo"]) == h:
                    m.append(r["leaf_index"])
        def_facts.append({"def": df["id"], "client": df["client"], "server_id": sid, "tool": df["tool"], "at": df["at"], "matches_leaves": m,
                          "label": ("FAIT : empreinte identique à la feuille signée %s" % m) if m else
                          ("aucune feuille signée identique" if sid else "UNKNOWN : serveur sans chronologie signée reliable")})
    dfx = {f["def"]: f for f in def_facts}
    results = []
    for c in calls:
        sid = sid_of(c["client"], c["server_name"])
        ids = (mapping.get(c["client"]) or {}).get(c["server_name"])
        r = {"call": c["id"], "client": c["client"], "server_name": c["server_name"], "tool": c["tool"], "at_lo": c["at_lo"], "at_hi": c["at_hi"],
             "at_source": c["at_source"], "server_id": sid,
             "server_id_source": ("configuration locale actuelle (--server-id) : %s" % ids) if ids else "UNKNOWN : absent des configurations lues"}
        if sid is None:
            r.update(verdict="UNKNOWN", why="aucune feuille reliable : server_id %s" % ("non signé dans le bundle (%s)" % ids if ids else "inconnu"),
                     version=None, vs_changes="UNKNOWN (aucune feuille reliable ; jamais 0)")
            results.append(r); continue
        if c["time_status"] != "OK" or c["at_lo"] is None:
            r.update(verdict="UNKNOWN", why="horodatage %s" % c["time_status"], version=None, vs_changes="UNKNOWN (horodatage)")
            results.append(r); continue
        lo, hi = _ts(c["at_lo"]), _ts(c["at_hi"])
        S = servers[sid]
        tl = S["timelines"].get(c["tool"])
        r["vs_changes"] = [{"leaf": w["leaf_index"], "window": [w.get("lower_bound"), w["upper_bound"]], "position": classify(lo, hi, w),
                            "label": "DÉDUCTION", "tool_changed_in_leaf": c["tool"] in w["tools_changed"]} for w in S["windows"]]
        r["signed"] = version_at(tl, lo, hi) if tl else {"status": "UNKNOWN", "basis": "UNKNOWN", "version": None,
                                                           "why": "outil absent de toutes les feuilles signées du serveur"}
        cand = [df for df in defs if df["client"] == c["client"] and df["server_name"] == c["server_name"] and df["tool"] == c["tool"]
                and (c["client"] != "claude-code" or df["session_ref"] == c["session_ref"])]
        prior = [df for df in cand if df["at"] and _ts(df["at"]) <= lo]
        later = [df for df in cand if df["at"] and _ts(df["at"]) > lo]
        if prior:
            df = max(prior, key=lambda x: (_ts(x["at"]), x["id"]))
            f = dfx[df["id"]]
            r["presented"] = {"def": df["id"], "at": df["at"], "matches_leaves": f["matches_leaves"],
                              "basis": "FAIT (empreinte)" if f["matches_leaves"] else "DÉFINITION SANS FEUILLE SIGNÉE IDENTIQUE",
                              "link": "dernière définition présentée avant l'appel (%s)" % ("même session" if c["client"] == "claude-code" else "même serveur, cache Cursor")}
            sv = r["signed"].get("version")
            hv = {_leaf_tool_hash(rr, c["tool"]) for rr in S["leaves"] if rr["leaf_index"] in f["matches_leaves"]}
            r["presented"]["consistent_with_signed_deduction"] = (None if sv is None else (sv in hv))
        else:
            r["presented"] = {"def": None, "basis": "UNKNOWN", "why": "aucune définition présentée antérieure reliée%s" %
                              (" (%d postérieure(s) à l'appel, non reliées)" % len(later) if later else "")}
        aud = [a for a in audit if a["server_id"] == sid and a["at"] and _ts(a["at"]) <= lo and str(a["event"]).startswith("tools/list")]
        if aud:
            a = max(aud, key=lambda x: (_ts(x["at"]), x["id"]))
            m = [rr["leaf_index"] for rr in S["leaves"] if rr["tools_fingerprint"]["sha256"] == a["live_tools_sha256"]]
            r["proxy_audit"] = {"audit": a["id"], "at": a["at"], "matches_leaves": m, "client": "UNKNOWN (le proxy n'enregistre pas le client)",
                                "label": ("FAIT (empreinte globale = feuille %s), rattachement à l'appel : DÉDUCTION par l'heure" % m) if m else "aucune feuille identique"}
        if r["presented"].get("matches_leaves"):
            r["verdict"] = "FAIT"
            r["why"] = "la définition de l'outil présentée au client avant l'appel a l'empreinte signée des feuilles %s" % r["presented"]["matches_leaves"]
            r["version"] = _leaf_tool_hash(next(rr for rr in S["leaves"] if rr["leaf_index"] == r["presented"]["matches_leaves"][0]), c["tool"])
            if r["presented"]["consistent_with_signed_deduction"] is False:
                r["verdict"] = "CONTRADICTION"
                r["why"] += " ; mais la déduction signée donne une autre version"
        else:
            r["verdict"] = r["signed"]["status"] if r["signed"]["status"] != "ENCADRE" else "DÉDUCTION"
            r["why"] = r["signed"]["why"]
            r["version"] = r["signed"].get("version")
        results.append(r)
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"schema": SCHEMA_OUT, "since": since, "cutoff": cutoff,
            "signed_log": log_report,
            "servers": {sid: {"coverage": S["coverage"], "leaves": [r["leaf_index"] for r in S["leaves"]], "change_windows": S["windows"],
                              "coverage_gaps": S["gaps"], "timelines": S["timelines"]} for sid, S in servers.items()},
            "calls": results, "definitions": def_facts, "counts": counts,
            "scope": {"sources": len(sources), "calls": len(calls), "definitions": len(defs), "audit_lines": len(audit),
                      "calls_before_since": spec.get("calls_before_since"), "excluded_sources": spec.get("excluded_sources")},
            "limits": LIMITS}


def render(res):
    L = ["# exposure-scan — rappel de lot des appels d'outils (depuis %s, coupure %s)" % (res["since"], res["cutoff"]), "",
         "Journal signé : tête %d (%s), signature %s. Feuilles vérifiées (signature + inclusion) : %s." % (
             res["signed_log"]["sth"]["tree_size"], res["signed_log"]["sth"]["timestamp"], res["signed_log"]["sth"]["signature"],
             ", ".join(sorted(res["signed_log"]["leaves"], key=int))), "",
         "Périmètre : %(sources)d sources lues, %(calls)d appels MCP retenus, %(definitions)d définitions présentées, %(audit_lines)d lignes d'audit ; "
         "%(calls_before_since)s appels antérieurs au 10/10 écartés." % res["scope"], "", "Verdicts : %s" % json.dumps(res["counts"], ensure_ascii=False, sort_keys=True), "",
         "## Appels", ""]
    for r in res["calls"]:
        L.append("### %s — %s · %s/%s · %s → %s" % (r["call"], r["client"], r["server_name"], r["tool"], r["at_lo"], r["at_hi"]))
        L.append("- server_id : %s (%s)" % (r["server_id"], r["server_id_source"]))
        L.append("- **verdict : %s** — %s" % (r["verdict"], r["why"]))
        if r.get("version"):
            L.append("- version (empreinte par outil) : `%s`" % r["version"])
        if isinstance(r.get("vs_changes"), list):
            L.append("- position vs feuilles (DÉDUCTION) : " + " ; ".join("%d %s%s" % (v["leaf"], v["position"], " (outil ajouté/modifié/retiré dans cette feuille)" if v["tool_changed_in_leaf"] else "")
                                                                        for v in r["vs_changes"]))
        else:
            L.append("- position vs feuilles : %s" % r["vs_changes"])
        if r.get("presented"):
            L.append("- définition présentée : %s" % json.dumps(r["presented"], ensure_ascii=False, sort_keys=True))
        if r.get("proxy_audit"):
            L.append("- audit du proxy : %s" % r["proxy_audit"]["label"])
        L.append("")
    L += ["## Chronologies signées", ""]
    for sid, S in res["servers"].items():
        L.append("### %s — feuilles %s ; couverture tête %d (%s)" % (sid, S["leaves"], S["coverage"]["head"]["tree_size"], S["coverage"]["head"]["timestamp"]))
        for w in S["change_windows"]:
            L.append("- feuille %d : fenêtre [%s, %s] ; outils modifiés %s" % (w["leaf_index"], w.get("lower_bound"), w["upper_bound"], w["tools_changed"]))
        L.append("- trous (UNOBSERVED) dans les fenêtres : %d" % len(S["coverage_gaps"]))
        L.append("")
    L += ["## Limites", ""] + ["- " + x for x in res["limits"]]
    return "\n".join(L) + "\n"
