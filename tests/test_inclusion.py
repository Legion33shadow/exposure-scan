#!/usr/bin/env python3
"""exposure-scan 0.1.1 : mode preuve d'inclusion (bundle de démonstration). Tests + mutants, résultats calculés.
Lancer sous unshare -rn (aucun réseau). Usage : test_inclusion.py DIST_DIR FULL_BUNDLE
  DIST_DIR    : dist construit par make_dist_v011.py (exposure-scan-cli-0.1.1/ + legion-log-demo-34964/)
  FULL_BUNDLE : bundle complet (comparaison des verdicts démo / complet)
Écrit uniquement sous cli/tests/_work/incl-<horodatage>/."""
import glob, json, os, py_compile, shutil, subprocess, sys
from datetime import datetime, timedelta, timezone

CLI = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST, FULL = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
CD = os.path.join(DIST, "exposure-scan-cli-0.1.1")
DEMO = os.path.join(DIST, "legion-log-demo-34964")
TS = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
WORK = os.path.join(CLI, "tests", "_work", "incl-" + TS)
RES = []
SERVERS = {"dex": "com.dexpaprika/dexpaprika", "jobs": "com.remoshift/jobs"}


def check(name, cond, detail=""):
    RES.append((name, bool(cond)))
    print("%s  %s%s" % ("PASS" if cond else "FAIL", name, ("  — " + str(detail)) if detail != "" else ""), flush=True)


def es(*args, home=None):
    """La CLI publiée (dist), lancée comme un inconnu : python3 -I, chemin du paquet explicite."""
    env = dict(os.environ, HOME=home) if home else None
    code = "import sys; sys.path.insert(0, sys.argv.pop(1)); from exposure_scan.__main__ import main; sys.exit(main())"
    p = subprocess.run(["python3", "-I", "-B", "-c", code, CD] + list(args), capture_output=True, text=True, env=env)
    return p.returncode, p.stdout + p.stderr


def last(o):
    return (o.strip().splitlines() or [""])[-1]


def jl(p):
    return [json.loads(l) for l in open(p) if l.strip()]


def wjl(p, rows):
    with open(p, "w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")


def man(d):
    return json.load(open(os.path.join(d, "BUNDLE_MANIFEST.json")))


def mut(tag, fn, *verify_args):
    """Copie du bundle de démo, mutation, manifeste recalculé (même mode, mêmes serveurs sauf si fn les change)."""
    sys.path.insert(0, CD)
    from exposure_scan.bundle import write_manifest
    d = os.path.join(WORK, "mut-" + tag); shutil.copytree(DEMO, d)
    m = man(d)
    servers = fn(d, m)
    if servers is not False:
        write_manifest(d, mode=m.get("mode"), servers=servers if servers is not None else m.get("servers"))
    return es("--verify-bundle", d, *verify_args)


def ts(s):
    return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def z(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def fake_home(times):
    """HOME factice : config Claude Code (--server-id du proxy legion-guard) + une transcription d'appels MCP."""
    h = os.path.join(WORK, "home"); os.makedirs(os.path.join(h, ".claude", "projects", "p"))
    rows, k = [], 0
    for server, tool, at in times:
        k += 1; end = z(ts(at) + timedelta(seconds=1))
        rows += [{"type": "user", "sessionId": "s1", "timestamp": at, "message": {"role": "user", "content": "SECRET-PROMPT-%d" % k}},
                 {"type": "assistant", "sessionId": "s1", "timestamp": at, "message": {"role": "assistant", "content": [
                     {"type": "tool_use", "id": "t%d" % k, "name": "mcp__%s__%s" % (server, tool), "input": {"q": "SECRET-ARG-%d" % k}}]}},
                 {"type": "user", "sessionId": "s1", "timestamp": end, "message": {"role": "user", "content": [
                     {"type": "tool_result", "tool_use_id": "t%d" % k, "content": "SECRET-RESULT-%d" % k}]}}]
    wjl(os.path.join(h, ".claude", "projects", "p", "s1.jsonl"), rows)
    g = lambda sid: {"command": "python", "args": ["-m", "legion_guard", "proxy", "--server-id", sid]}
    json.dump({"projects": {"/w": {"mcpServers": {"dex": g(SERVERS["dex"]), "jobs": g(SERVERS["jobs"]), "absent": g("io.example/not-in-demo"),
                                                  "nowhere": {"command": "npx", "args": ["x"]}}}}}, open(os.path.join(h, ".claude.json"), "w"))
    return h


def main():
    os.makedirs(WORK)
    bad = []
    for p in sorted(glob.glob(os.path.join(CD, "**", "*.py"), recursive=True)) + sorted(glob.glob(os.path.join(CLI, "*.py"))):
        try:
            py_compile.compile(p, doraise=True, cfile=os.path.join(WORK, "pyc", os.path.basename(p) + "c"))
        except py_compile.PyCompileError as e:
            bad.append(str(e))
    check("I00 py_compile de chaque .py (CLI publiée + scripts)", not bad, "; ".join(bad))
    rc, o = es("--version"); check("I01 version 0.1.1", rc == 0 and "0.1.1" in o, o.strip())
    rc, o = es("--verify-bundle", DEMO, "--full")
    check("I02 bundle de démo --full (clé épinglée) -> VALIDE", rc == 0 and "RESULTAT : VALIDE" in o and "mode preuve d'inclusion" in o, " | ".join(o.strip().splitlines()[1:4])[:300])
    rc, o = es("--verify-bundle", DEMO)
    check("I03 bundle de démo, mode rapide -> VALIDE (mêmes contrôles en mode inclusion)", rc == 0 and "RESULTAT : VALIDE" in o, last(o))
    size = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(DEMO) for f in fs)
    tgz = os.path.join(DIST, "legion-log-demo-34964.tar.gz")
    check("I04 démo < 10 Mo (dossier et archive)", size < 10e6 and os.path.getsize(tgz) < 10e6, "%d octets, archive %d octets" % (size, os.path.getsize(tgz)))
    rc, o = es("--verify-bundle", FULL)
    check("I05 rétrocompat : bundle complet (mode rapide) -> VALIDE, racine recalculée sur toutes les feuilles", rc == 0 and "racine recalculée sur 34964 feuilles" in o, last(o))
    # ---------- mutants ----------
    recs = jl(os.path.join(DEMO, "tlog", "records.jsonl"))
    dex = [r for r in recs if r["server_id"] == SERVERS["dex"]]
    i0 = dex[1]["leaf_index"]

    def m1(d, m):
        p = os.path.join(d, "tlog", "proofs", "INC-%d.json" % i0); pr = json.load(open(p))
        h = pr["audit_path"][3]; pr["audit_path"][3] = ("0" if h[0] != "0" else "1") + h[1:]; json.dump(pr, open(p, "w"))
    rc, o = mut("proof", m1); check("M1 preuve falsifiée (1 nœud du chemin) -> INVALIDE", rc == 1 and "preuve d'inclusion fausse" in o, last(o))

    def m2(d, m):
        p = os.path.join(d, "tlog", "records.jsonl")
        wjl(p, [dict(r, observed_at="2026-10-15T00:00:00Z") if r["leaf_index"] == i0 else r for r in jl(p)])
    rc, o = mut("leaf", m2); check("M2 feuille absente de la tête (contenu changé, preuve gardée) -> INVALIDE", rc == 1 and "absente de la tête signée" in o, last(o))

    def m3(d, m):
        p = os.path.join(d, "tlog", "records.jsonl"); rows = jl(p); j = rows[-1]["leaf_index"]
        rows[-1]["leaf_index"] = 40000; wjl(p, rows)
        pp = os.path.join(d, "tlog", "proofs", "INC-%d.json" % j); pr = json.load(open(pp)); pr["leaf_index"] = 40000
        os.remove(pp); json.dump(pr, open(os.path.join(d, "tlog", "proofs", "INC-40000.json"), "w"))
    rc, o = mut("index", m3); check("M3 index hors de l'arbre (40000 ≥ 34964) -> INVALIDE", rc == 1 and "hors de l'arbre" in o, last(o))

    def m4(d, m):
        sp = glob.glob(os.path.join(d, "tlog", "sth_*.json"))[0]; s = json.load(open(sp)); s["tree_head"]["timestamp"] = "2026-10-24T00:00:00Z"; json.dump(s, open(sp, "w"))
    rc, o = mut("sth", m4); check("M4 tête mal signée (horodatage changé) -> INVALIDE", rc == 1 and "signature de la tête" in o, last(o))
    other = next(r for r in jl(os.path.join(FULL, "tlog", "records.jsonl")) if r["server_id"] not in man(DEMO)["servers"]
                 and os.path.exists(os.path.join(FULL, "tlog", "proofs", "LCI-%d.json" % r["leaf_index"])))
    olci = json.load(open(os.path.join(FULL, "tlog", "proofs", "LCI-%d.json" % other["leaf_index"])))

    def m5(d, m):
        pr = dict(olci); pr["leaf_index"] = i0; json.dump(pr, open(os.path.join(d, "tlog", "proofs", "INC-%d.json" % i0), "w"))
    rc, o = mut("otherproof", m5); check("M5 preuve d'un autre serveur (chemin valide de la feuille %d) -> INVALIDE" % other["leaf_index"], rc == 1 and "preuve d'inclusion fausse" in o, last(o))

    def m5b(d, m):
        p = os.path.join(d, "tlog", "records.jsonl"); wjl(p, sorted(jl(p) + [other], key=lambda r: r["leaf_index"]))
        json.dump(olci, open(os.path.join(d, "tlog", "proofs", "INC-%d.json" % other["leaf_index"]), "w"))
    rc, o = mut("otherleaf", m5b); check("M5b feuille VALIDE d'un serveur non déclaré ajoutée (avec sa vraie preuve) -> INVALIDE", rc == 1 and "serveurs déclarés" in o, last(o))

    def m6(d, m):
        p = os.path.join(d, "tlog", "records.jsonl"); wjl(p, [r for r in jl(p) if r["leaf_index"] != i0]); os.remove(os.path.join(d, "tlog", "proofs", "INC-%d.json" % i0))
    rc, o = mut("chain", m6); check("M6 feuille du milieu retirée (chaîne prev_leaf_index) -> INVALIDE", rc == 1 and "sous-ensemble incomplet" in o, last(o))
    # dernière feuille d'un serveur déclaré, observée par la couverture : rien ne la référence dans la chaîne
    sys.path.insert(0, CD)
    from exposure_scan import load_engine
    E = load_engine(); COV, MV = E[5], E[6]
    obs = {}
    for s in man(DEMO)["servers"]:
        h = MV.server_hash(s); p = "%02x" % COV.shard_of(h)
        for f in glob.glob(os.path.join(DEMO, "coverage", "cycles", "*", p + ".json")):
            for e in json.load(open(f))["entries"]:
                if e["h"] == h and e["s"] == "OBSERVED" and e["fp"]:
                    obs.setdefault(s, set()).add(e["fp"])
    tail = None
    for s in man(DEMO)["servers"]:
        rs = [r for r in recs if r["server_id"] == s]
        if rs[-1]["tools_fingerprint"]["sha256"] in obs.get(s, set()) and sum(1 for r in rs if r["tools_fingerprint"]["sha256"] == rs[-1]["tools_fingerprint"]["sha256"]) == 1:
            tail = rs[-1]; break
    check("M7a mutant effectif : une dernière feuille de serveur observée par un cycle signé existe", tail is not None, tail and "%s feuille %d" % (tail["server_id"], tail["leaf_index"]))
    if tail:
        def m7(d, m):
            p = os.path.join(d, "tlog", "records.jsonl"); wjl(p, [r for r in jl(p) if r["leaf_index"] != tail["leaf_index"]])
            os.remove(os.path.join(d, "tlog", "proofs", "INC-%d.json" % tail["leaf_index"]))
        rc, o = mut("tail", m7); check("M7 dernière feuille retirée (aucune feuille ne la référence) -> INVALIDE par la couverture signée", rc == 1 and "feuille retirée" in o, last(o))

    def m8(d, m):
        from exposure_scan.bundle import write_manifest
        write_manifest(d); return False
    rc, o = mut("nomode", m8); check("M8 marqueur de mode retiré du manifeste -> INVALIDE (mode complet exige tout l'arbre)", rc == 1 and "feuilles pour une tête" in o, last(o))

    def m9(d, m):
        f = sorted(glob.glob(os.path.join(d, "coverage", "cycles", "7", "*.json")))[0]; sd = json.load(open(f)); sd["entries"] = sd["entries"][1:]; json.dump(sd, open(f, "w"))
    rc, o = mut("shard", m9); check("M9 tranche de couverture tronquée -> INVALIDE", rc == 1 and "tranche" in o, last(o))

    def m10(d, m):
        return sorted(m["servers"] + ["io.example/declared-without-leaves"])
    rc, o = mut("decl", m10); check("M10 serveur déclaré sans feuille -> INVALIDE", rc == 1 and "serveurs déclarés" in o, last(o))

    def m11(d, m):
        m["mode"] = "partial"; json.dump(m, open(os.path.join(d, "BUNDLE_MANIFEST.json"), "w")); return False
    rc, o = mut("badmode", m11); check("M11 mode inconnu dans le manifeste -> INVALIDE", rc == 1 and "mode inconnu" in o, last(o))
    # ---------- bout en bout sur HOME factice ----------
    dx = [ts(r["observed_at"]) for r in dex]
    jb = [ts(r["observed_at"]) for r in recs if r["server_id"] == SERVERS["jobs"]]
    times = [("dex", "getNetworks", z(dx[0] + (dx[1] - dx[0]) / 2)), ("dex", "search", z(dx[-1] + timedelta(minutes=30))),
             ("jobs", "search_jobs", z(jb[5] + (jb[6] - jb[5]) / 2)), ("absent", "x", z(dx[1])), ("nowhere", "z", z(dx[1]))]
    H = fake_home(times)
    dirs = ["--client-dir", H + "/.claude", "--client-dir", H + "/.claude.json"]
    D = os.path.join(WORK, "dossier-demo")
    rc, o = es(*dirs, "--log-bundle", DEMO, "--out", D, home=H)
    check("E1 CLI (dist 0.1.1) sur HOME factice + bundle de démo -> dossier", rc == 0 and os.path.isfile(os.path.join(D, "result.json")) and "bundle de démonstration" in o,
          " | ".join(l.strip() for l in o.splitlines() if "CALL-" in l or "verdicts" in l))
    if rc != 0:
        print(o); return finish()
    res = json.load(open(os.path.join(D, "result.json")))
    v = {(r["server_name"], r["tool"]): r["verdict"] for r in res["calls"]}
    check("E2 5 appels classés", len(res["calls"]) == 5, json.dumps(res["counts"], ensure_ascii=False, sort_keys=True))
    check("E3 serveurs de la démo (dex, jobs) : verdict signé, jamais UNKNOWN", all(v.get(k) not in (None, "UNKNOWN") for k in (("dex", "getNetworks"), ("dex", "search"), ("jobs", "search_jobs"))),
          {"%s/%s" % k: x for k, x in v.items()})
    check("E4 serveur hors démo et serveur sans --server-id : UNKNOWN", v.get(("absent", "x")) == "UNKNOWN" and v.get(("nowhere", "z")) == "UNKNOWN")
    p = subprocess.run(["sh", os.path.join(D, "VERIFY.sh")], capture_output=True, text=True)
    check("E5 dossier : VERIFY.sh niveau 1 (hors ligne) -> VALIDE", p.returncode == 0 and "RESULTAT : VALIDE" in p.stdout + p.stderr, last(p.stdout + p.stderr))
    rc, o = es("--verify", D, "--log-bundle", DEMO)
    check("E6 dossier ↔ bundle de démo : croisement -> VALIDE", rc == 0 and "croisement bundle" in o, last(o))
    spec = json.load(open(os.path.join(D, "inputs.json")))
    check("E7 le dossier déclare le mode du bundle (producer.bundle_mode = inclusion)", spec["producer"].get("bundle_mode") == "inclusion" and spec["producer"].get("bundle_servers") == man(DEMO)["servers"])
    bl = b"".join(open(os.path.join(x, f), "rb").read() for x, _, fs in os.walk(D) for f in fs if "/tools" not in x)
    check("E8 vie privée : 0 SECRET-* dans le dossier", b"SECRET-" not in bl, "SECRET-: %d" % bl.count(b"SECRET-"))
    D2 = os.path.join(WORK, "dossier-full")
    rc, o = es(*dirs, "--log-bundle", FULL, "--out", D2, home=H)
    v2 = {(r["server_name"], r["tool"]): r["verdict"] for r in json.load(open(os.path.join(D2, "result.json")))["calls"]} if rc == 0 else {}
    same = {k: (v[k], v2.get(k)) for k in v if k[0] in ("dex", "jobs")}
    check("E9 mêmes verdicts démo / bundle complet pour les serveurs de la démo", rc == 0 and all(a == b for a, b in same.values()), {"%s/%s" % k: x for k, x in same.items()})
    return finish()


def finish():
    k = sum(1 for _, ok in RES if ok)
    print("\n%d/%d réussis, %d échoué(s)" % (k, len(RES), len(RES) - k))
    return 0 if k == len(RES) else 1


if __name__ == "__main__":
    sys.exit(main())
