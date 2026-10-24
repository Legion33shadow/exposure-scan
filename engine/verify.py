#!/usr/bin/env python3
"""exposure-scan : vérifieur hors ligne d'un dossier. Aucun réseau.
Niveau 1 (partout) : MANIFEST exact (aucun fichier en trop/manquant, empreintes) ; outils = copies déclarées ;
  re-dérivation complète (journal signé, inclusion, couverture signée, classement) identique à result.json et RESULT.md.
Niveau 2 (--sources, machine d'origine) : relit le préfixe déclaré de chaque source locale, exige le même SHA-256, ré-extrait
  et exige des appels / définitions / audit / correspondances identiques à ceux du dossier.
Sortie : « RESULTAT : VALIDE » (code 0) ou « RESULTAT : INVALIDE » + raison (code 1)."""
import hashlib, json, os, sys

D = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
sys.path.insert(0, os.path.join(D, "tools")); sys.path.insert(0, os.path.join(D, "tools", "vendor"))


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fail(msg):
    print("RESULTAT : INVALIDE —", msg)
    sys.exit(1)


def main():
    mp = os.path.join(D, "MANIFEST.json")
    if not os.path.isfile(mp):
        fail("MANIFEST.json absent")
    man = json.load(open(mp))["files"]
    present = sorted(os.path.relpath(os.path.join(d, f), D) for d, _, fs in os.walk(D) for f in fs
                     if "__pycache__" not in d and f not in ("MANIFEST.json", "SHA256SUMS"))
    if present != sorted(man):
        fail("fichiers en trop %s / manquants %s" % (sorted(set(present) - set(man)), sorted(set(man) - set(present))))
    for f, h in man.items():
        if sha(open(os.path.join(D, f), "rb").read()) != h:
            fail("empreinte différente : %s" % f)
    print("1/3 MANIFEST : %d fichiers conformes ; MANIFEST sha256 %s (à comparer à une valeur obtenue hors bande)" % (len(man), sha(open(mp, "rb").read())))
    import scan  # noqa: E402  (copie du dossier, déjà couverte par MANIFEST)
    try:
        res = scan.derive(D)
    except scan.InvalidCase as e:
        fail("re-dérivation refusée : %s" % e)
    dump = json.dumps(res, sort_keys=True, ensure_ascii=False, indent=1) + "\n"
    if dump != open(os.path.join(D, "result.json"), encoding="utf-8").read():
        fail("result.json diffère de la re-dérivation")
    if scan.render(res) != open(os.path.join(D, "RESULT.md"), encoding="utf-8").read():
        fail("RESULT.md diffère de la re-dérivation")
    s = res["signed_log"]
    print("2/3 re-dérivation identique : tête %d signée VERIFIED ; feuilles %s (signature + inclusion) ; couverture %s"
          % (s["sth"]["tree_size"], ",".join(sorted(s["leaves"], key=int)),
             "; ".join("%s tête %d, %d cycles" % (k, v["coverage"]["head"]["tree_size"], len(v["coverage"]["cycles_verified"])) for k, v in res["servers"].items())))
    if "--sources" in sys.argv:
        import readers as R  # noqa: E402
        spec = json.load(open(os.path.join(D, "inputs.json")))
        srcs = json.load(open(os.path.join(D, spec["artifacts"]["x_sources"]["path"])))
        home = os.path.expanduser("~")

        def rd(s):
            p = s["path"].replace("~", home, 1)
            if not os.path.isfile(p):
                fail("source absente : %s" % s["path"])
            b = open(p, "rb").read()[:s["bytes_used"]]
            if len(b) != s["bytes_used"] or sha(b) != s["sha256_prefix"]:
                fail("source modifiée (préfixe) : %s" % s["path"])
            return b, s["mtime_ns"]
        ext = R.extract([{"kind": s["kind"], "path": s["path"], "server_name": s.get("server_name")} for s in srcs], lambda s: rd(next(x for x in srcs if x["path"] == s["path"])),
                        spec["since"], spec["cutoff"])
        for name in ("calls", "defs", "audit"):
            got = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in ext[name])
            if got != open(os.path.join(D, spec["artifacts"]["x_" + name]["path"]), encoding="utf-8").read():
                fail("ré-extraction différente : %s" % name)
        if json.dumps(ext["mapping"], sort_keys=True) != json.dumps(json.load(open(os.path.join(D, spec["artifacts"]["x_mapping"]["path"]))), sort_keys=True):
            fail("ré-extraction différente : mapping")
        print("3/3 sources locales : %d préfixes identiques, ré-extraction identique" % len(srcs))
    else:
        print("3/3 sources locales : non vérifiées (option --sources, machine d'origine seulement)")
    print("verdicts : %s" % json.dumps(res["counts"], ensure_ascii=False, sort_keys=True))
    print("RESULTAT : VALIDE")


if __name__ == "__main__":
    main()
