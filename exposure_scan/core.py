"""Découverte des sources dans les dossiers clients fournis, extraction (engine/readers.py), dossier au format du moteur
(vérifiable par engine/verify.py copié dans le dossier), contrôle croisé dossier ↔ bundle, suggestions de correspondance."""
import glob, hashlib, json, os, shutil
from datetime import datetime, timezone
from . import Refused, __version__
from .bundle import sha_file


def _mt(p):
    return os.stat(p).st_mtime


def discover(client_dirs, since_ts):
    """Ne lit QUE ce qui est sous les chemins fournis. Type reconnu par la structure :
    - dossier Claude Code (~/.claude)        : projects/**/*.jsonl
    - fichier ~/.claude.json                 : configuration MCP Claude Code (--server-id du proxy legion-guard)
    - dossier Cursor (~/.cursor)             : projects/*/agent-transcripts/**/*.jsonl, projects/*/mcps/*/tools/*.json, mcp.json
    - dossier de config Cursor (~/.config/Cursor) : logs/*/window*/workbench.mcp.allowlist.log
    Transcriptions dont le dernier mtime précède since : écartées et comptées."""
    S, excluded, kinds = [], [], {}
    for raw in client_dirs:
        d = os.path.abspath(os.path.expanduser(raw))
        found = []
        if os.path.isfile(d):
            if os.path.basename(d) == ".claude.json":
                found.append({"kind": "claude_config", "path": d})
            elif os.path.basename(d) == "mcp.json":
                found.append({"kind": "cursor_config", "path": d})
            else:
                raise Refused("fichier non reconnu : %s (attendu .claude.json ou mcp.json)" % raw)
        elif os.path.isdir(d):
            for p in sorted(glob.glob(os.path.join(d, "projects", "*", "agent-transcripts", "**", "*.jsonl"), recursive=True)):
                found.append({"kind": "cursor_transcript", "path": p, "_t": 1})
            cur = {x["path"] for x in found}
            for p in sorted(glob.glob(os.path.join(d, "projects", "**", "*.jsonl"), recursive=True)):
                if p not in cur and "/agent-transcripts/" not in p:
                    found.append({"kind": "claude_transcript", "path": p, "_t": 1})
            for td in sorted(glob.glob(os.path.join(d, "projects", "*", "mcps", "*", "tools"))):
                for f in sorted(os.listdir(td)):
                    if f.endswith(".json"):
                        found.append({"kind": "cursor_tool", "path": os.path.join(td, f), "server_name": os.path.basename(os.path.dirname(td)), "_t": 1})
            for p in sorted(glob.glob(os.path.join(d, "logs", "*", "window*", "workbench.mcp.allowlist.log"))):
                found.append({"kind": "cursor_log", "path": p, "_t": 1})
            if os.path.isfile(os.path.join(d, "mcp.json")) and glob.glob(os.path.join(d, "projects")):
                found.append({"kind": "cursor_config", "path": os.path.join(d, "mcp.json")})
            if not found:
                raise Refused("aucune source reconnue sous %s" % raw)
        else:
            raise Refused("chemin absent : %s" % raw)
        for s in found:
            t = s.pop("_t", 0)
            if t and _mt(s["path"]) < since_ts:
                excluded.append(s)
            else:
                S.append(s)
            kinds[s["kind"]] = kinds.get(s["kind"], 0) + 1
    seen, out = set(), []
    for s in S:
        if s["path"] not in seen:
            seen.add(s["path"]); out.append(s)
    return out, excluded, kinds


def suggestions(ext, bundle, R):
    """DÉDUCTION, jamais appliquée : pour chaque (client, serveur) présenté, les server_id du bundle dont une feuille porte
    exactement les mêmes empreintes par outil pour TOUS les outils présentés. À confirmer puis passer par --map."""
    idx = {}
    for r in bundle.recs:
        fp = r.get("tools_fingerprint") or {}
        for t, h in fp.get("per_tool_sha256", []):
            idx.setdefault((fp.get("algo"), t, h), set()).add(r["server_id"])
    groups = {}
    for d in ext["defs"]:
        groups.setdefault((d["client"], d["server_name"]), {}).setdefault(d["tool"], d["per_tool_sha256"])
    out = []
    for (client, name), tools in sorted(groups.items()):
        cand = None
        for t, hs in tools.items():
            ids = set().union(*[idx.get((a, t, h), set()) for a, h in hs.items()])
            cand = ids if cand is None else cand & ids
        out.append({"client": client, "server_name": name, "tools_presented": len(tools), "candidates": sorted(cand or []),
                    "label": "DÉDUCTION (empreintes par outil identiques) — non appliquée ; confirmer puis --map"})
    return out


def build(out, client_dirs, bundle, E, since, maps, redact):
    _, R, S, B, VT, COV, MV = E
    if os.path.exists(out):
        raise Refused("refus : %s existe déjà" % out)
    home = os.path.expanduser("~")
    cutoff = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    srcs, excluded, kinds = discover(client_dirs, R.ts(since).timestamp())
    snap = {}

    def live(s):
        if s["path"] not in snap:
            b = open(s["path"], "rb").read()
            snap[s["path"]] = (b, os.stat(s["path"]).st_mtime_ns)
        return snap[s["path"]]
    ext = R.extract(srcs, live, since, cutoff)
    prov = {}
    for c, m in ext["mapping"].items():
        for k, v in m.items():
            prov["%s:%s" % (c, k)] = {"server_ids": v, "source": "configuration locale (--server-id du proxy legion-guard)"}
    for spec in maps:
        try:
            left, sid = spec.split("=", 1)
            client, name = left.split(":", 1)
        except ValueError:
            raise Refused("--map attendu sous la forme client:nom_serveur=server_id (ex. cursor:user-foo=io.github.x/foo)")
        ext["mapping"].setdefault(client, {})[name] = [sid]
        prov["%s:%s" % (client, name)] = {"server_ids": [sid], "source": "MANUELLE (--map) : affirmée par l'utilisateur, non vérifiée"}

    def show(p):
        if redact:
            return "redacted:" + hashlib.sha256(p.encode()).hexdigest()[:16]
        return "~" + p[len(home):] if p.startswith(home + os.sep) else p
    sources = []
    for i, s in enumerate(srcs):
        b, mt = snap[s["path"]]
        sources.append({"id": "S%03d" % i, "kind": s["kind"], "path": show(s["path"]), "bytes_used": len(b),
                        "sha256_prefix": hashlib.sha256(b).hexdigest(), "mtime_ns": mt, "server_name": s.get("server_name"), "note": None})
    wanted = sorted({x for m in ext["mapping"].values() for ids in m.values() for x in ids if not x.startswith("<")})
    by_sid = {}
    for r in bundle.recs:
        if r["server_id"] in wanted:
            by_sid.setdefault(r["server_id"], []).append(r["leaf_index"])
    A = os.path.join(out, "artifacts")
    for d in ("tlog/proofs", "coverage/cycles", "extract"):
        os.makedirs(os.path.join(A, d))
    arts = {}

    def put(aid, rel_bundle, rel, role, prov_):
        src = bundle.p(*rel_bundle.split("/"))
        shutil.copyfile(src, os.path.join(A, rel))
        arts[aid] = {"path": "artifacts/" + rel, "role": role, "provenance": prov_, "source": "bundle:" + rel_bundle, "source_sha256": sha_file(src)}
    leaves = sorted(li for v in by_sid.values() for li in v)
    with open(os.path.join(A, "tlog", "records.jsonl"), "w") as f:
        for li in leaves:
            f.write(json.dumps(bundle.rec(li), sort_keys=True, ensure_ascii=False) + "\n")
    arts["tlog_records"] = {"path": "artifacts/tlog/records.jsonl", "role": "tlog_records", "provenance": "signed_log",
                            "source": "bundle:tlog/records.jsonl, feuilles %s" % leaves, "source_sha256": sha_file(bundle.p("tlog", "records.jsonl"))}
    proofs = []
    n = bundle.sth["tree_head"]["tree_size"]
    for li in leaves:
        p = {"leaf_index": li, "tree_size": n, "audit_path": bundle.inclusion_path(li), "computed_by": "exposure_scan %s (RFC 6962 PATH)" % __version__}
        lci = bundle.p("tlog", "proofs", "LCI-%d.json" % li)
        if os.path.exists(lci):
            if json.load(open(lci))["audit_path"] != p["audit_path"]:
                raise Refused("preuve recalculée ≠ preuve LCI du bundle (feuille %d)" % li)
            p["equals_bundle_proof"] = "LCI-%d.json" % li
        open(os.path.join(A, "tlog", "proofs", "%d.json" % li), "w").write(B.dump(p))
        arts["proof_%d" % li] = {"path": "artifacts/tlog/proofs/%d.json" % li, "role": "tlog_proof", "provenance": "signed_log (chemin recalculé)", "source": "calcul local"}
        proofs.append("proof_%d" % li)
    sthname = os.path.basename(bundle.sth_path)
    put("tlog_sth", "tlog/" + sthname, "tlog/" + sthname, "tlog_sth", "signed_log")
    put("tlog_keyring", "tlog/keyring.jsonl", "tlog/keyring.jsonl", "tlog_keyring", "signed_log")
    put("tlog_root", "tlog/legion_root.b64", "tlog/legion_root.b64", "tlog_root", "clé racine (%s)" % bundle.pin_status)
    put("cov_head", "coverage/head.json", "coverage/head.json", "coverage_head", "signed_coverage")
    put("cov_pubkey", "coverage/pubkey.txt", "coverage/pubkey.txt", "coverage_pubkey", "clé de couverture (à comparer hors bande)")
    put("cov_index", "coverage/cycles/index.json", "coverage/cycles/index.json", "coverage_index", "signed_coverage")
    cycles, servers = {}, {}
    for i in range(bundle.cov_head["tree_size"]):
        put("cov_cycle_%d" % i, "coverage/cycles/%d.json" % i, "coverage/cycles/%d.json" % i, "coverage_cycle", "signed_coverage")
        cycles[str(i)] = "cov_cycle_%d" % i
    for sid in sorted(by_sid):
        p = "%02x" % COV.shard_of(MV.server_hash(sid))
        shards = {}
        for i in range(bundle.cov_head["tree_size"]):
            rel = "coverage/cycles/%d/%s.json" % (i, p)
            if os.path.exists(bundle.p(*rel.split("/"))):
                os.makedirs(os.path.join(A, "coverage", "cycles", str(i)), exist_ok=True)
                aid = "cov_shard_%d_%s" % (i, p)
                if aid not in arts:
                    put(aid, rel, rel, "coverage_shard", "signed_coverage")
                shards[str(i)] = aid
        servers[sid] = shards
    for name, rows in (("calls", ext["calls"]), ("defs", ext["defs"]), ("audit", ext["audit"])):
        with open(os.path.join(A, "extract", name + ".jsonl"), "w") as f:
            for r in rows:
                f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
        arts["x_" + name] = {"path": "artifacts/extract/%s.jsonl" % name, "role": name, "provenance": "extraction locale (engine/readers.py, non signée)"}
    for name, obj, role, pv in (("sources", sources, "sources", "engagements SHA-256 des préfixes lus"),
                                ("mapping", ext["mapping"], "mapping", "configurations locales (--server-id) + --map"),
                                ("cursor_logs", ext["cursor_logs"], "cursor_logs", "contrôle du décalage horaire"),
                                ("mapping_provenance", prov, "mapping_provenance", "origine de chaque correspondance"),
                                ("suggestions", suggestions(ext, bundle, R), "suggestions", "DÉDUCTION non appliquée")):
        open(os.path.join(A, "extract", name + ".json"), "w").write(B.dump(obj))
        arts["x_" + name] = {"path": "artifacts/extract/%s.json" % name, "role": role, "provenance": pv}
    spec = {"schema": S.SCHEMA_IN, "since": since, "cutoff": cutoff, "artifacts": arts,
            "signed_log": {"records": "tlog_records", "sth": "tlog_sth", "keyring": "tlog_keyring", "root": "tlog_root", "proofs": proofs},
            "coverage": {"head": "cov_head", "pubkey": "cov_pubkey", "index": "cov_index", "cycles": cycles},
            "servers": servers,
            "extract": {"calls": "x_calls", "defs": "x_defs", "audit": "x_audit", "sources": "x_sources", "mapping": "x_mapping"},
            "calls_before_since": ext["calls_before_since"],
            "excluded_sources": {"count": len(excluded), "reason": "transcriptions dont le dernier mtime précède %s" % since,
                                 "paths": [show(e["path"]) for e in excluded]},
            "producer": {"tool": "exposure_scan %s" % __version__, "bundle_manifest_sha256": bundle.manifest_sha, "pin_status": bundle.pin_status,
                         "bundle_mode": bundle.mode, "bundle_servers": bundle.servers,
                         "paths_redacted": bool(redact), "manual_maps": len(maps)}}
    open(os.path.join(out, "inputs.json"), "w").write(B.dump(spec))
    eng = E[0]
    os.makedirs(os.path.join(out, "tools", "vendor"))
    for t in B.TOOLS:
        shutil.copyfile(os.path.join(eng, t), os.path.join(out, "tools", t))
    res = S.derive(out)
    open(os.path.join(out, "result.json"), "w").write(B.dump(res))
    open(os.path.join(out, "RESULT.md"), "w").write(S.render(res))
    open(os.path.join(out, "VERIFY.sh"), "w").write(
        "#!/bin/sh\n# Vérification hors ligne de niveau 1 (aucun réseau, aucune source locale). Recommandé : unshare -rn sh VERIFY.sh\n"
        "# Option, sur la machine d'origine seulement : sh VERIFY.sh --sources (relit les préfixes des sources locales).\n"
        "cd \"$(dirname \"$0\")\" && exec python3 -I -B tools/verify.py . \"$@\"\n")
    m = B.write_manifest(out)
    return res, m, kinds, len(excluded)


def cross_check(dossier, bundle, log=print):
    """Le dossier est-il bâti sur CE bundle ? Fichiers signés octet pour octet identiques, feuilles = lignes du bundle,
    preuves = chemins recalculés sur le bundle. Un dossier valide tout seul mais issu d'un autre journal est refusé."""
    spec = json.load(open(os.path.join(dossier, "inputs.json")))
    arts = spec["artifacts"]
    for aid, a in sorted(arts.items()):
        src = a.get("source", "")
        if src.startswith("bundle:") and aid != "tlog_records":
            rel = src[len("bundle:"):]
            if sha_file(os.path.join(dossier, a["path"])) != sha_file(bundle.p(*rel.split("/"))):
                raise Refused("dossier ≠ bundle : %s" % rel)
    n = 0
    for l in open(os.path.join(dossier, arts["tlog_records"]["path"])):
        if l.strip():
            r = json.loads(l)
            if json.dumps(r, sort_keys=True) != json.dumps(bundle.rec(r["leaf_index"]), sort_keys=True):
                raise Refused("dossier ≠ bundle : feuille %d" % r["leaf_index"])
            pr = json.load(open(os.path.join(dossier, arts["proof_%d" % r["leaf_index"]]["path"])))
            if pr["audit_path"] != bundle.inclusion_path(r["leaf_index"]) or pr["tree_size"] != bundle.sth["tree_head"]["tree_size"]:
                raise Refused("dossier ≠ bundle : preuve %d" % r["leaf_index"])
            n += 1
    if spec.get("producer", {}).get("bundle_manifest_sha256") not in (None, bundle.manifest_sha):
        raise Refused("dossier produit avec un autre bundle (BUNDLE_MANIFEST %s…)" % spec["producer"]["bundle_manifest_sha256"][:16])
    log("croisement dossier ↔ bundle : %d feuilles, preuves et fichiers signés identiques au bundle" % n)
