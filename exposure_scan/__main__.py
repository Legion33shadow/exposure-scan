"""Point d'entrée unique.

  python3 -m exposure_scan --client-dir ~/.claude --client-dir ~/.claude.json --client-dir ~/.cursor \\
                           --client-dir ~/.config/Cursor --log-bundle <BUNDLE> --out <DIR>
  python3 -m exposure_scan --verify <DOSSIER> [--log-bundle <BUNDLE>]     # niveau 1 (+ croisement avec le bundle)
  python3 -m exposure_scan --verify-bundle <BUNDLE> [--full]               # contrôle du bundle seul

Options : --since 2026-10-10T00:00:00Z (défaut), --map client:nom=server_id (répétable, correspondance manuelle),
--redact-paths (chemins des sources remplacés par une empreinte ; le niveau 2 --sources devient impossible),
--test-key (accepte un bundle signé par une clé non épinglée : tests uniquement, signalé dans le dossier).
Codes de retour : 0 = VALIDE / dossier écrit ; 1 = INVALIDE / refus ; 2 = usage."""
import argparse, json, os, subprocess, sys
from . import Refused, load_engine, __version__


def main(argv=None):
    ap = argparse.ArgumentParser(prog="exposure_scan", description="Quelle version signée de l'outil était en service lors de chaque appel ? (hors ligne)")
    ap.add_argument("--client-dir", action="append", default=[])
    ap.add_argument("--log-bundle")
    ap.add_argument("--out")
    ap.add_argument("--since", default="2026-10-10T00:00:00Z")
    ap.add_argument("--map", action="append", default=[])
    ap.add_argument("--redact-paths", action="store_true")
    ap.add_argument("--test-key", action="store_true")
    ap.add_argument("--verify")
    ap.add_argument("--verify-bundle")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--version", action="version", version="exposure_scan " + __version__)
    a = ap.parse_args(argv)
    try:
        E = load_engine()
        from .bundle import Bundle
        from . import core
        if a.verify_bundle:
            Bundle(a.verify_bundle, E, a.test_key).check("full" if a.full else "quick")
            print("RESULTAT : VALIDE"); return 0
        if a.verify:
            d = os.path.abspath(a.verify)
            if not os.path.isfile(os.path.join(d, "tools", "verify.py")):
                raise Refused("dossier sans tools/verify.py")
            p = subprocess.run([sys.executable, "-I", "-B", os.path.join(d, "tools", "verify.py"), d], capture_output=True, text=True)
            sys.stdout.write(p.stdout + p.stderr)
            if p.returncode != 0:
                return 1
            if a.log_bundle:
                core.cross_check(d, Bundle(a.log_bundle, E, a.test_key).check("quick"))
                print("RESULTAT : VALIDE (dossier + croisement bundle)")
            return 0
        if not (a.client_dir and a.log_bundle and a.out):
            ap.print_usage(); print("--client-dir, --log-bundle et --out sont requis"); return 2
        b = Bundle(a.log_bundle, E, a.test_key).check("quick")
        res, m, kinds, nexcl = core.build(a.out, a.client_dir, b, E, a.since, a.map, a.redact_paths)
        print("sources reconnues : %s ; écartées (avant %s) : %d" % (json.dumps(kinds, sort_keys=True), a.since, nexcl))
        print("dossier : %s\nMANIFEST sha256 : %s" % (os.path.abspath(a.out), m))
        print("appels : %d ; verdicts : %s" % (len(res["calls"]), json.dumps(res["counts"], ensure_ascii=False, sort_keys=True)))
        for r in res["calls"]:
            pos = ",".join(sorted({v["position"] for v in r["vs_changes"]})) if isinstance(r.get("vs_changes"), list) else "UNKNOWN"
            print("  %s %-11s %s/%s %s  %s  positions[%s]" % (r["call"], r["client"], r["server_name"], r["tool"], r["at_lo"], r["verdict"], pos))
        print("vérifier hors ligne : unshare -rn sh %s/VERIFY.sh" % os.path.abspath(a.out))
        return 0
    except Refused as e:
        print("RESULTAT : INVALIDE —", e); return 1
    except Exception as e:
        if type(e).__name__ == "InvalidCase":  # refus du moteur (engine/scan.py) : provenance ou signature invalide
            print("RESULTAT : INVALIDE — moteur :", e); return 1
        raise


if __name__ == "__main__":
    sys.exit(main())
