"""exposure-scan : outil autonome, hors ligne. « Quelle version SIGNÉE de l'outil était en service lors de chaque appel ? »

Réutilise le moteur engine/ (readers.py, scan.py, build.py, vendor/) par import, sans le modifier : les fichiers importés
sont contrôlés contre ENGINE.sha256 avant tout import. Aucun réseau. Lecture seule des dossiers clients."""
import hashlib, os, sys

__version__ = "0.1.1"
HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE_FILES = ("readers.py", "scan.py", "build.py", "verify.py", "vendor/exposure.py", "vendor/verify_tlog.py", "vendor/cov.py",
                "vendor/merkle_v1.py", "vendor/jcs.py", "vendor/SOURCES.sha256")


class Refused(Exception):
    """Refus : bundle, moteur ou dossier non conforme. Le message est affiché après « RESULTAT : INVALIDE »."""


def engine_dir():
    for c in (os.path.join(os.path.dirname(HERE), "engine"), os.path.join(os.path.dirname(os.path.dirname(HERE)), "engine")):
        if os.path.isfile(os.path.join(c, "scan.py")):
            return c
    raise Refused("moteur engine/ introuvable à côté du paquet")


def load_engine():
    """Contrôle les empreintes du moteur (ENGINE.sha256) puis l'importe. Un moteur modifié est refusé."""
    eng = engine_dir()
    want = {}
    for l in open(os.path.join(HERE, "ENGINE.sha256")):
        if l.strip():
            h, f = l.split(None, 1)
            want[f.strip()] = h
    for f in ENGINE_FILES:
        p = os.path.join(eng, f)
        if not os.path.isfile(p) or hashlib.sha256(open(p, "rb").read()).hexdigest() != want.get(f):
            raise Refused("moteur modifié ou incomplet : %s" % f)
    for p in (eng, os.path.join(eng, "vendor")):
        if p not in sys.path:
            sys.path.insert(0, p)
    import readers, scan, build, verify_tlog, cov, merkle_v1  # noqa: E401
    return eng, readers, scan, build, verify_tlog, cov, merkle_v1
