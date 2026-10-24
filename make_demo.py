#!/usr/bin/env python3
"""Bundle de DÉMONSTRATION (mode preuve d'inclusion) extrait d'un bundle complet, en LECTURE SEULE.
Pour les serveurs choisis : toutes leurs feuilles signées (lignes copiées octet pour octet), une preuve INC-<i>.json par
feuille (chemin RFC 6962 recalculé sur l'arbre complet, comparé à la preuve LCI publiée quand elle existe), tête signée,
checkpoint C2SP, trousseau, clé racine ; couverture : tête, index, les cycles, et les seules tranches de ces serveurs.
Refus si la cible existe. Usage : make_demo.py FULL_BUNDLE OUT_DIR SERVER_ID [SERVER_ID ...]"""
import json, os, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from exposure_scan import load_engine, __version__  # noqa: E402
from exposure_scan.bundle import Bundle, INCLUSION, sha_file, write_manifest  # noqa: E402


def copy(src, dst):
    if os.path.exists(dst):
        raise SystemExit("refus : %s existe déjà" % dst)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(src, dst)


def main(full, out, servers):
    if os.path.exists(out):
        raise SystemExit("refus : %s existe déjà" % out)
    E = load_engine()
    eng, R, S, B, VT, COV, MV = E
    fb = Bundle(full, E).check("quick", log=lambda *_: None)
    if fb.mode != "full-tree":
        raise SystemExit("la source doit être un bundle complet")
    servers = sorted(set(servers))
    n = fb.sth["tree_head"]["tree_size"]
    lines = [l for l in open(fb.p("tlog", "records.jsonl")) if l.strip()]
    keep = [i for i, r in enumerate(fb.recs) if r["server_id"] in servers]
    miss = sorted(set(servers) - {fb.recs[i]["server_id"] for i in keep})
    if miss:
        raise SystemExit("serveurs absents du journal : %s" % miss)
    os.makedirs(os.path.join(out, "tlog", "proofs"))
    with open(os.path.join(out, "tlog", "records.jsonl"), "w") as f:
        for i in keep:
            f.write(lines[i] if lines[i].endswith("\n") else lines[i] + "\n")
    nlci = 0
    for i in keep:
        ap = fb.inclusion_path(i)
        lci = fb.p("tlog", "proofs", "LCI-%d.json" % i)
        if os.path.exists(lci):
            if json.load(open(lci))["audit_path"] != ap:
                raise SystemExit("chemin recalculé ≠ preuve LCI publiée (feuille %d)" % i)
            nlci += 1
        pr = {"id": "INC-%d" % i, "leaf_index": i, "tree_size": n, "audit_path": ap,
              "computed_by": "make_demo.py %s (RFC 6962 PATH sur l'arbre complet)" % __version__}
        if not VT.check_inclusion(fb.recs[i], pr, fb.sth):
            raise SystemExit("preuve non vérifiable (feuille %d)" % i)
        open(os.path.join(out, "tlog", "proofs", "INC-%d.json" % i), "w").write(json.dumps(pr, sort_keys=True, indent=1) + "\n")
    for f in ("keyring.jsonl", "legion_root.b64", "log_vkey.json", os.path.basename(fb.sth_path), "checkpoint_%d.note" % n):
        if os.path.exists(fb.p("tlog", f)):
            copy(fb.p("tlog", f), os.path.join(out, "tlog", f))
    for f in ("head.json", "pubkey.txt", "cycles/index.json"):
        copy(fb.p("coverage", *f.split("/")), os.path.join(out, "coverage", *f.split("/")))
    pref = sorted({COV.shard_of(MV.server_hash(s)) for s in servers})
    nsh = 0
    for i in range(fb.cov_head["tree_size"]):
        copy(fb.p("coverage", "cycles", "%d.json" % i), os.path.join(out, "coverage", "cycles", "%d.json" % i))
        if json.load(open(fb.p("coverage", "cycles", "%d.json" % i)))["state"] == "MISSED":
            continue
        for p in pref:
            copy(fb.p("coverage", "cycles", str(i), "%02x.json" % p), os.path.join(out, "coverage", "cycles", str(i), "%02x.json" % p))
            nsh += 1
    prov = {"kind": "demo subset (mode preuve d'inclusion)", "source_bundle_manifest_sha256": fb.manifest_sha,
            "source_tree_size": n, "servers": servers, "leaves": keep, "leaves_with_published_LCI_equal": nlci,
            "coverage_shards": nsh, "coverage_shard_prefixes": ["%02x" % p for p in pref],
            "note": "Sous-ensemble du journal signé : seules les feuilles de ces serveurs. Tout autre serveur est absent (UNKNOWN)."}
    open(os.path.join(out, "PROVENANCE.json"), "w").write(json.dumps(prov, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    m = write_manifest(out, mode=INCLUSION, servers=servers)
    print("demo : %d feuilles sur %d (%d égales à une preuve LCI publiée), %d serveurs, %d tranches ; BUNDLE_MANIFEST sha256 %s"
          % (len(keep), n, nlci, len(servers), nsh, m))


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3:])
