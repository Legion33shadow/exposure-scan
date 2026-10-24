#!/usr/bin/env python3
"""exposure-scan : construit le dossier OUT (qui ne doit pas exister) à partir des sources locales (LECTURE SEULE) et du
bundle signé declaration-record-20261023 (LECTURE SEULE). Aucun réseau, aucune écriture hors OUT.
Usage : build.py OUT [--since 2026-10-10T00:00:00Z]"""
import hashlib, json, os, shutil, sys
from datetime import datetime, timezone

_H = os.path.dirname(os.path.abspath(__file__))
for _p in (_H, os.path.join(_H, "vendor")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import verify_tlog as VT  # noqa: E402
import cov as COV  # noqa: E402
import merkle_v1 as MV  # noqa: E402
import readers as R  # noqa: E402
import scan  # noqa: E402

HOME = os.path.expanduser("~")
B = os.path.join(HOME, "legion-control-plane", "packages", "declaration-record-20261023", "bundle")
TOOLS = ["scan.py", "readers.py", "verify.py", "vendor/exposure.py", "vendor/verify_tlog.py", "vendor/cov.py", "vendor/merkle_v1.py",
         "vendor/jcs.py", "vendor/SOURCES.sha256"]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def tilde(p):
    return "~" + p[len(HOME):] if p.startswith(HOME + os.sep) else p


def mth(hs):
    if len(hs) == 1:
        return hs[0]
    k = 1 << ((len(hs) - 1).bit_length() - 1)
    return VT.node_hash(mth(hs[:k]), mth(hs[k:]))


def path(m, hs):
    if len(hs) == 1:
        return []
    k = 1 << ((len(hs) - 1).bit_length() - 1)
    return path(m, hs[:k]) + [mth(hs[k:])] if m < k else path(m - k, hs[k:]) + [mth(hs[:k])]


def dump(o):
    return json.dumps(o, sort_keys=True, ensure_ascii=False, indent=1) + "\n"


def write_manifest(out):
    files = sorted(os.path.relpath(os.path.join(d, f), out) for d, _, fs in os.walk(out) for f in fs
                   if "__pycache__" not in d and f not in ("MANIFEST.json", "SHA256SUMS"))
    man = {"schema": "legion-exposure-scan-manifest/0.1", "files": {f: sha(open(os.path.join(out, f), "rb").read()) for f in files}}
    open(os.path.join(out, "MANIFEST.json"), "w").write(dump(man))
    with open(os.path.join(out, "SHA256SUMS"), "w") as f:
        for p in files + ["MANIFEST.json"]:
            f.write("%s  %s\n" % (sha(open(os.path.join(out, p), "rb").read()), p))
    return sha(open(os.path.join(out, "MANIFEST.json"), "rb").read())


def main(out, since="2026-10-10T00:00:00Z"):
    if os.path.exists(out):
        raise SystemExit("refus : %s existe déjà" % out)
    cutoff = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    srcs, excluded = R.discover(HOME, R.ts(since).timestamp())
    snap = {}

    def live(s):  # lecture unique, figée : octets + mtime au moment de l'extraction
        if s["path"] not in snap:
            b = open(s["path"], "rb").read()
            snap[s["path"]] = (b, os.stat(s["path"]).st_mtime_ns)
        return snap[s["path"]]

    ext = R.extract(srcs, live, since, cutoff)
    sources = []
    for i, s in enumerate(srcs):
        b, mt = snap[s["path"]]
        sources.append({"id": "S%03d" % i, "kind": s["kind"], "path": tilde(s["path"]), "bytes_used": len(b), "sha256_prefix": sha(b),
                        "mtime_ns": mt, "server_name": s.get("server_name"), "note": s.get("note")})
    # serveurs reliables : server_id déclaré (--server-id) dans une configuration ET présent dans le journal signé
    recs = [json.loads(l) for l in open(os.path.join(B, "tlog", "records.jsonl"))]
    sth = json.load(open(os.path.join(B, "tlog", "sth_34964.json")))
    assert len(recs) == sth["tree_head"]["tree_size"]
    hs = [VT.leaf_hash(VT.canon(r)) for r in recs]
    assert mth(hs).hex() == sth["tree_head"]["root_sha256"], "racine recalculée différente de la tête signée"
    wanted = sorted({x for m in ext["mapping"].values() for ids in m.values() for x in ids if not x.startswith("<")})
    by_sid = {}
    for r in recs:
        if r["server_id"] in wanted:
            by_sid.setdefault(r["server_id"], []).append(r["leaf_index"])
    A = os.path.join(out, "artifacts")
    for d in ("tlog/proofs", "coverage/cycles", "extract"):
        os.makedirs(os.path.join(A, d))
    arts = {}

    def put(aid, src, rel, role, prov):
        shutil.copy2(src, os.path.join(A, rel))
        arts[aid] = {"path": "artifacts/" + rel, "role": role, "provenance": prov, "source": tilde(src), "source_sha256": sha(open(src, "rb").read())}

    leaves = sorted(li for v in by_sid.values() for li in v)
    with open(os.path.join(A, "tlog", "records.jsonl"), "w") as f:
        for li in leaves:
            f.write(json.dumps(recs[li], sort_keys=True, ensure_ascii=False) + "\n")
    arts["tlog_records"] = {"path": "artifacts/tlog/records.jsonl", "role": "tlog_records", "provenance": "signed_log",
                            "source": "bundle/tlog/records.jsonl, feuilles %s" % leaves, "source_sha256": sha(open(os.path.join(B, "tlog", "records.jsonl"), "rb").read())}
    proofs = []
    for li in leaves:
        p = {"leaf_index": li, "tree_size": len(hs), "audit_path": [x.hex() for x in path(li, hs)], "computed_by": "engine/build.py (RFC 6962 PATH)"}
        lci = os.path.join(B, "tlog", "proofs", "LCI-%d.json" % li)
        if os.path.exists(lci):
            assert json.load(open(lci))["audit_path"] == p["audit_path"], "preuve recalculée != preuve LCI du bundle"
            p["equals_bundle_proof"] = "LCI-%d.json" % li
        open(os.path.join(A, "tlog", "proofs", "%d.json" % li), "w").write(dump(p))
        arts["proof_%d" % li] = {"path": "artifacts/tlog/proofs/%d.json" % li, "role": "tlog_proof", "provenance": "signed_log (chemin recalculé)", "source": "calcul local"}
        proofs.append("proof_%d" % li)
    put("tlog_sth", os.path.join(B, "tlog", "sth_34964.json"), "tlog/sth_34964.json", "tlog_sth", "signed_log")
    put("tlog_keyring", os.path.join(B, "tlog", "keyring.jsonl"), "tlog/keyring.jsonl", "tlog_keyring", "signed_log")
    put("tlog_root", os.path.join(B, "tlog", "legion_root.b64"), "tlog/legion_root.b64", "tlog_root", "clé racine épinglée (à comparer hors bande)")
    put("cov_head", os.path.join(B, "coverage", "head.json"), "coverage/head.json", "coverage_head", "signed_coverage")
    put("cov_pubkey", os.path.join(B, "coverage", "pubkey.txt"), "coverage/pubkey.txt", "coverage_pubkey", "clé de couverture (à comparer hors bande)")
    put("cov_index", os.path.join(B, "coverage", "cycles", "index.json"), "coverage/cycles/index.json", "coverage_index", "signed_coverage")
    ncyc = len(json.load(open(os.path.join(B, "coverage", "cycles", "index.json")))["leaves"])
    cycles, servers = {}, {}
    for i in range(ncyc):
        put("cov_cycle_%d" % i, os.path.join(B, "coverage", "cycles", "%d.json" % i), "coverage/cycles/%d.json" % i, "coverage_cycle", "signed_coverage")
        cycles[str(i)] = "cov_cycle_%d" % i
    for sid in sorted(by_sid):
        p = "%02x" % COV.shard_of(MV.server_hash(sid))
        shards = {}
        for i in range(ncyc):
            src = os.path.join(B, "coverage", "cycles", str(i), p + ".json")
            if os.path.exists(src):
                os.makedirs(os.path.join(A, "coverage", "cycles", str(i)), exist_ok=True)
                aid = "cov_shard_%d_%s" % (i, p)
                if aid not in arts:
                    put(aid, src, "coverage/cycles/%d/%s.json" % (i, p), "coverage_shard", "signed_coverage")
                shards[str(i)] = aid
        servers[sid] = shards
    for name, rows in (("calls", ext["calls"]), ("defs", ext["defs"]), ("audit", ext["audit"])):
        with open(os.path.join(A, "extract", name + ".jsonl"), "w") as f:
            for r in rows:
                f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
        arts["x_" + name] = {"path": "artifacts/extract/%s.jsonl" % name, "role": name, "provenance": "extraction locale (readers.py, non signée)"}
    open(os.path.join(A, "extract", "sources.json"), "w").write(dump(sources))
    open(os.path.join(A, "extract", "mapping.json"), "w").write(dump(ext["mapping"]))
    open(os.path.join(A, "extract", "cursor_logs.json"), "w").write(dump(ext["cursor_logs"]))
    arts["x_sources"] = {"path": "artifacts/extract/sources.json", "role": "sources", "provenance": "engagements SHA-256 des préfixes lus"}
    arts["x_mapping"] = {"path": "artifacts/extract/mapping.json", "role": "mapping", "provenance": "configurations locales (--server-id)"}
    arts["x_cursor_logs"] = {"path": "artifacts/extract/cursor_logs.json", "role": "cursor_logs", "provenance": "contrôle du décalage horaire"}
    spec = {"schema": scan.SCHEMA_IN, "since": since, "cutoff": cutoff, "artifacts": arts,
            "signed_log": {"records": "tlog_records", "sth": "tlog_sth", "keyring": "tlog_keyring", "root": "tlog_root", "proofs": proofs},
            "coverage": {"head": "cov_head", "pubkey": "cov_pubkey", "index": "cov_index", "cycles": cycles},
            "servers": servers,
            "extract": {"calls": "x_calls", "defs": "x_defs", "audit": "x_audit", "sources": "x_sources", "mapping": "x_mapping"},
            "calls_before_since": ext["calls_before_since"],
            "excluded_sources": {"count": len(excluded), "reason": "transcriptions dont le dernier mtime précède %s" % since,
                                 "paths": [tilde(e["path"]) for e in excluded]}}
    open(os.path.join(out, "inputs.json"), "w").write(dump(spec))
    os.makedirs(os.path.join(out, "tools", "vendor"))
    for t in TOOLS:
        shutil.copy2(os.path.join(_H, t), os.path.join(out, "tools", t))
    res = scan.derive(out)
    open(os.path.join(out, "result.json"), "w").write(dump(res))
    open(os.path.join(out, "RESULT.md"), "w").write(scan.render(res))
    open(os.path.join(out, "VERIFY.sh"), "w").write(
        "#!/bin/sh\n# Vérification hors ligne (aucun réseau). Recommandé : unshare -rn sh VERIFY.sh\n"
        "# Option, sur la machine d'origine seulement : sh VERIFY.sh --sources (relit les préfixes des sources locales).\n"
        "cd \"$(dirname \"$0\")\" && exec python3 -I -B tools/verify.py . \"$@\"\n")
    m = write_manifest(out)
    print("dossier : %s\nappels : %d ; verdicts : %s\nMANIFEST sha256 : %s" % (out, len(res["calls"]), res["counts"], m))


if __name__ == "__main__":
    a = sys.argv[1:]
    main(a[0], *(a[2:3] if len(a) > 2 and a[1] == "--since" else []))
