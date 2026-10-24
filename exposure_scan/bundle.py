"""Bundle autonome du journal signé : contrôle hors ligne.

Disposition attendue (copie lecture seule) :
  BUNDLE_MANIFEST.json                 {schema, files: {chemin: sha256}} — aucun fichier en trop ni manquant
  tlog/records.jsonl                   toutes les feuilles signées (index 0..N-1)
  tlog/sth_<N>.json                    tête signée Ed25519
  tlog/keyring.jsonl, legion_root.b64  trousseau + clé racine (épinglée : verify_tlog.ROOT_PIN)
  tlog/checkpoint_<N>.note, log_vkey.json   checkpoint C2SP + clé de vérification (contrôlés si présents)
  tlog/proofs/LCI-<i>.json             preuves d'inclusion publiées (contrôlées en mode complet)
  coverage/head.json, pubkey.txt, cycles/index.json, cycles/<i>.json, cycles/<i>/<pp>.json   couverture signée
check(mode="quick") : manifeste, épinglage, trousseau, tête, racine RFC 6962 recalculée sur toutes les feuilles, tête de
couverture + index. mode="full" ajoute : signature de chaque feuille, chaque preuve LCI, chaque cycle, chaque tranche."""
import base64, glob, hashlib, json, os
from . import Refused


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def list_files(d):
    return sorted(os.path.relpath(os.path.join(x, f), d) for x, _, fs in os.walk(d) for f in fs
                  if "__pycache__" not in x and f not in ("BUNDLE_MANIFEST.json", "SHA256SUMS"))


def write_manifest(d):
    man = {"schema": "legion-log-bundle-manifest/0.1", "files": {f: sha_file(os.path.join(d, f)) for f in list_files(d)}}
    open(os.path.join(d, "BUNDLE_MANIFEST.json"), "w").write(json.dumps(man, sort_keys=True, indent=1) + "\n")
    with open(os.path.join(d, "SHA256SUMS"), "w") as f:
        for p in list_files(d) + ["BUNDLE_MANIFEST.json"]:
            f.write("%s  %s\n" % (sha_file(os.path.join(d, p)), p))
    return sha_file(os.path.join(d, "BUNDLE_MANIFEST.json"))


class Bundle:
    def __init__(self, d, E, test_key=False):
        self.dir, self.E, self.test_key = os.path.abspath(d), E, test_key
        sths = glob.glob(os.path.join(self.dir, "tlog", "sth_*.json"))
        if len(sths) != 1:
            raise Refused("bundle : il faut exactement une tête tlog/sth_<N>.json (%d trouvées)" % len(sths))
        self.sth_path = sths[0]

    def p(self, *a):
        return os.path.join(self.dir, *a)

    def check(self, mode="quick", log=print):
        _, R, S, B, VT, COV, MV = self.E
        mp = self.p("BUNDLE_MANIFEST.json")
        if not os.path.isfile(mp):
            raise Refused("bundle : BUNDLE_MANIFEST.json absent")
        man = json.load(open(mp))["files"]
        have = list_files(self.dir)
        if have != sorted(man):
            raise Refused("bundle : fichiers en trop %s / manquants %s" % (sorted(set(have) - set(man))[:5], sorted(set(man) - set(have))[:5]))
        for f, h in man.items():
            if sha_file(self.p(f)) != h:
                raise Refused("bundle : empreinte différente : %s" % f)
        self.manifest_sha = sha_file(mp)
        log("bundle 1/4 manifeste : %d fichiers conformes ; BUNDLE_MANIFEST sha256 %s (à comparer hors bande)" % (len(man), self.manifest_sha))
        root = open(self.p("tlog", "legion_root.b64")).read().strip()
        self.root_pin = VT.key_pin(root)
        if self.root_pin != VT.ROOT_PIN:
            if not self.test_key:
                raise Refused("bundle : clé racine %s… non épinglée (attendu %s…) ; --test-key seulement pour un bundle de test" % (self.root_pin[:16], VT.ROOT_PIN[:16]))
            self.pin_status = "CLÉ DE TEST NON ÉPINGLÉE (--test-key)"
        else:
            self.pin_status = "clé racine = ROOT_PIN épinglé dans verify_tlog.py"
        try:
            keys = VT.load_keyring(open(self.p("tlog", "keyring.jsonl")).read(), root)
        except Exception as e:
            raise Refused("bundle : trousseau refusé (%s)" % e)
        sth = json.load(open(self.sth_path))
        if not VT.check_sth(sth, keys):
            raise Refused("bundle : signature de la tête invalide")
        recs = [json.loads(l) for l in open(self.p("tlog", "records.jsonl")) if l.strip()]
        n = sth["tree_head"]["tree_size"]
        if len(recs) != n or any(r.get("leaf_index") != i for i, r in enumerate(recs)):
            raise Refused("bundle : %d feuilles pour une tête de taille %d, ou index non contigus" % (len(recs), n))
        hs = [VT.leaf_hash(VT.canon(r)) for r in recs]
        if B.mth(hs).hex() != sth["tree_head"]["root_sha256"]:
            raise Refused("bundle : racine RFC 6962 recalculée différente de la tête signée")
        self.sth, self.recs, self.hs, self.keys = sth, recs, hs, keys
        log("bundle 2/4 journal : %s ; tête %d (%s) signée ; racine recalculée sur %d feuilles = tête" % (self.pin_status, n, sth["tree_head"]["timestamp"], n))
        note = self.p("tlog", "checkpoint_%d.note" % n)
        if os.path.isfile(note):
            lines = open(note).read().split("\n")
            if len(lines) < 3 or lines[1] != str(n) or base64.b64decode(lines[2]).hex() != sth["tree_head"]["root_sha256"]:
                raise Refused("bundle : checkpoint C2SP incohérent avec la tête signée")
            vk = json.load(open(self.p("tlog", "log_vkey.json")))
            ok = sorted(k for k in ("log_vkey", "origin_vkey") if vk.get(k) and VT.verify_witnessed(open(note).read(), vk[k], [], 0).get("log_signature"))
            if not ok:
                raise Refused("bundle : checkpoint C2SP : aucune signature valide pour log_vkey.json")
            self.checkpoint = "checkpoint C2SP taille %d = tête, signé (%s)" % (n, ", ".join(ok))
        else:
            self.checkpoint = "checkpoint absent"
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(open(self.p("coverage", "pubkey.txt")).read().strip()))
        try:
            head = COV.verify_head_doc(json.load(open(self.p("coverage", "head.json"))), pub)
        except MV.VerifyError as e:
            raise Refused("bundle : couverture : %s" % e)
        idx = json.load(open(self.p("coverage", "cycles", "index.json")))
        leaves = [MV.unb64(x) for x in idx.get("leaves", [])]
        if len(leaves) != head["tree_size"] or MV.b64(MV.mth(leaves)) != head["root"]:
            raise Refused("bundle : index de couverture incohérent avec la tête signée")
        self.cov_head, self.cov_leaves = head, leaves
        self.cov_pin = hashlib.sha256(open(self.p("coverage", "pubkey.txt"), "rb").read().strip()).hexdigest()
        log("bundle 3/4 %s ; couverture tête %d (%s) signée, index conforme ; clé de couverture sha256 %s… (hors bande)"
            % (self.checkpoint, head["tree_size"], head["timestamp"], self.cov_pin[:16]))
        if mode != "full":
            log("bundle 4/4 mode rapide : signatures individuelles, preuves LCI et tranches non parcourues (VERIFY_BUNDLE.sh le fait)")
            return self
        bad = [r["leaf_index"] for r in recs if not all(VT.check_record(r, keys)[:2])]
        if bad:
            raise Refused("bundle : %d feuille(s) à signature/intégrité invalide (ex. %s)" % (len(bad), bad[:3]))
        nlci = 0
        for f in sorted(glob.glob(self.p("tlog", "proofs", "LCI-*.json"))):
            pr = json.load(open(f))
            if not VT.check_inclusion(recs[pr["leaf_index"]], pr, sth):
                raise Refused("bundle : preuve d'inclusion fausse : %s" % os.path.basename(f))
            nlci += 1
        nsh = 0
        for i in range(head["tree_size"]):
            cd = json.load(open(self.p("coverage", "cycles", "%d.json" % i)))
            if cd.get("slot") != i or MV.leaf_hash(MV.cycle_leaf_bytes(cd)) != leaves[i]:
                raise Refused("bundle : cycle %d altéré ou absent de la tête" % i)
            if cd["state"] == "MISSED":
                continue
            for p in range(COV.NSHARD):
                try:
                    COV.verify_shard(json.load(open(self.p("coverage", "cycles", str(i), "%02x.json" % p))), i, p, cd["entries_root"])
                except (MV.VerifyError, OSError, KeyError) as e:
                    raise Refused("bundle : cycle %d tranche %02x : %s" % (i, p, e))
                nsh += 1
        log("bundle 4/4 mode complet : %d signatures de feuilles, %d preuves LCI, %d cycles, %d tranches vérifiés" % (len(recs), nlci, head["tree_size"], nsh))
        return self

    def inclusion_path(self, li):
        B = self.E[3]
        return [x.hex() for x in B.path(li, self.hs)]
