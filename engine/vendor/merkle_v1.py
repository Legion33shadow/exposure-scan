#!/usr/bin/env python3
"""COVERAGE_V1 — registre de couverture signé par cycle (Phase 3, préproduction, rien de public).

Structure
  - Un cycle planifié (créneau cron, toutes les 6 h depuis SCHEDULE_START) = UNE feuille du journal de couverture
    (arbre de Merkle RFC 6962 : feuille = SHA-256(0x00 || données), nœud = SHA-256(0x01 || g || d)).
  - Données de la feuille (JCS RFC 8785) : {"type":"COVERAGE_V1","slot":i,"slot_start":..,"state":"RAN"|"MISSED",
    "run_id":..,"n":N,"entries_root":R}. R est la racine RFC 6962 d'un arbre interne sur les entrées du cycle,
    triées par server_hash : {"h":server_hash,"s":"OBSERVED"|"NOT_OBSERVED","fp":empreinte|null,"r":raison|null}.
  - Tête signée Ed25519 : {"type":"COVERAGE_V1_HEAD","log":..,"tree_size":n,"root":..,"timestamp":..}.
  - Fichier statique par serveur /tlog/v0/server/<server_hash>.json : pour CHAQUE créneau, soit une preuve
    d'inclusion de son entrée, soit une preuve d'absence (deux voisines consécutives qui l'encadrent), soit
    MISSED ; plus la preuve d'inclusion de chaque feuille de cycle dans la tête. Rien ne peut être omis.

Règle stricte
  UNCHANGED_SINCE(d) seulement si TOUS les créneaux planifiés depuis d ont observé le serveur avec la même
  empreinte que le dernier créneau. Dernier créneau non observé, trou (MISSED, NOT_OBSERVED, absent) ou
  empreinte différente avant d -> UNKNOWN pour toute date antérieure.
"""
import base64, hashlib, json, sys, os
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jcs import canonicalize, loads_strict  # RFC 8785, déjà utilisé par le journal de prod

LOG_NAME = "legion-coverage-v1-preprod"
SLOT_HOURS = 6


class VerifyError(Exception):
    pass


# ---------- RFC 6962 / RFC 9162 ----------
def H(b):
    return hashlib.sha256(b).digest()


def leaf_hash(data):
    return H(b"\x00" + data)


def node_hash(l, r):
    return H(b"\x01" + l + r)


def _k(n):  # plus grande puissance de 2 strictement inférieure à n
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):  # leaves = hachés de feuilles
    n = len(leaves)
    if n == 0:
        return H(b"")
    if n == 1:
        return leaves[0]
    k = _k(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def inclusion_path(m, leaves):
    n = len(leaves)
    if n <= 1:
        return []
    k = _k(n)
    if m < k:
        return inclusion_path(m, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_path(m - k, leaves[k:]) + [mth(leaves[:k])]


def verify_inclusion(leaf_index, tree_size, lh, path, root):
    """RFC 9162 §2.1.3.2."""
    if leaf_index >= tree_size:
        return False
    fn, sn, r = leaf_index, tree_size - 1, lh
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


class Tree:
    """Arbre RFC 6962 avec MTH des sous-arbres mémoïsée (O(n) une fois, puis preuves en O(log n))."""
    def __init__(self, leaves):
        self.lv, self.memo = leaves, {}

    def mth(self, lo, hi):
        if hi - lo == 0:
            return H(b"")
        if hi - lo == 1:
            return self.lv[lo]
        r = self.memo.get((lo, hi))
        if r is None:
            k = _k(hi - lo)
            r = self.memo[(lo, hi)] = node_hash(self.mth(lo, lo + k), self.mth(lo + k, hi))
        return r

    def root(self):
        return self.mth(0, len(self.lv))

    def path(self, m, lo=0, hi=None):
        hi = len(self.lv) if hi is None else hi
        if hi - lo <= 1:
            return []
        k = _k(hi - lo)
        if m < k:
            return self.path(m, lo, lo + k) + [self.mth(lo + k, hi)]
        return self.path(m - k, lo + k, hi) + [self.mth(lo, lo + k)]


def consistency_proof(m, leaves):
    def sub(m, lv, b):
        n = len(lv)
        if m == n:
            return [] if b else [mth(lv)]
        k = _k(n)
        if m <= k:
            return sub(m, lv[:k], b) + [mth(lv[k:])]
        return sub(m - k, lv[k:], False) + [mth(lv[:k])]
    return sub(m, leaves, True) if 0 < m < len(leaves) else []


def verify_consistency(n1, n2, root1, root2, proof):
    """RFC 9162 §2.1.4.2."""
    if n1 == n2:
        return root1 == root2 and not proof
    if n1 == 0 or n1 > n2 or not proof:
        return False
    if n1 & (n1 - 1) == 0:
        proof = [root1] + proof
    fn, sn = n1 - 1, n2 - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == root1 and sr == root2


b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s, validate=True)


def server_hash(server_id):
    return hashlib.sha256(server_id.encode("utf-8")).hexdigest()


def entry_bytes(e):
    return canonicalize({"h": e["h"], "s": e["s"], "fp": e.get("fp"), "r": e.get("r")})


def cycle_leaf_bytes(c):
    return canonicalize({k: c.get(k) for k in ("type", "slot", "slot_start", "state", "run_id", "run_finished", "n", "entries_root")})


# ---------- signature ----------
def sign_head(priv, head):
    return b64(priv.sign(canonicalize(head)))


def verify_head(pub, head, sig):
    from cryptography.exceptions import InvalidSignature
    if head.get("type") != "COVERAGE_V1_HEAD":
        raise VerifyError("type de tête invalide")
    try:
        pub.verify(unb64(sig), canonicalize(head))
    except (InvalidSignature, ValueError) as e:
        raise VerifyError("signature de tête invalide") from e


# ---------- construction ----------
def slots(start, until):
    out, t = [], start
    while t + timedelta(hours=SLOT_HOURS) <= until:  # seuls les créneaux révolus
        out.append(t)
        t += timedelta(hours=SLOT_HOURS)
    return out


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def build(slot_list, cycles, priv, timestamp):
    """slot_list : datetimes ; cycles : {slot_index: {"run_id":..,"entries":{server_hash:(state,fp,reason)}}}.
    Retourne (head, sig, cycle_docs, inner_trees). Un créneau sans cycle = MISSED."""
    docs, inner = [], []
    for i, t in enumerate(slot_list):
        c = cycles.get(i)
        if c is None:
            docs.append({"type": "COVERAGE_V1", "slot": i, "slot_start": iso(t), "state": "MISSED",
                         "run_id": None, "run_finished": None, "n": 0, "entries_root": b64(mth([]))})
            inner.append(([], Tree([])))
            continue
        es = [{"h": h, "s": s, "fp": fp, "r": r} for h, (s, fp, r) in sorted(c["entries"].items())]
        tr = Tree([leaf_hash(entry_bytes(e)) for e in es])
        docs.append({"type": "COVERAGE_V1", "slot": i, "slot_start": iso(t), "state": "RAN",
                     "run_id": c["run_id"], "run_finished": c["run_finished"], "n": len(es), "entries_root": b64(tr.root())})
        inner.append((es, tr))
    outer = Tree([leaf_hash(cycle_leaf_bytes(d)) for d in docs])
    head = {"type": "COVERAGE_V1_HEAD", "log": LOG_NAME, "tree_size": len(docs), "root": b64(outer.root()),
            "timestamp": timestamp}
    return head, sign_head(priv, head), docs, inner, outer


def server_file(sid, head, sig, docs, inner, outer):
    h = server_hash(sid)
    cyc = []
    for i, d in enumerate(docs):
        es, lhs = inner[i]
        item = {"cycle": d, "cycle_proof": [b64(x) for x in outer.path(i)]}
        if d["state"] == "RAN":
            keys = [e["h"] for e in es]
            import bisect
            j = bisect.bisect_left(keys, h)
            if j < len(keys) and keys[j] == h:
                item["entry"] = {"index": j, "e": es[j], "proof": [b64(x) for x in lhs.path(j)]}
            else:  # absence : voisines j-1 et j (bornes possibles)
                item["absent"] = [{"index": k, "e": es[k], "proof": [b64(x) for x in lhs.path(k)]}
                                  for k in (j - 1, j) if 0 <= k < len(es)]
        cyc.append(item)
    f = {"type": "COVERAGE_V1_SERVER", "server_id": sid, "server_hash": h, "head": head, "head_sig": sig, "cycles": cyc}
    f["verdict"] = verdict_from_states(states_of(f))
    return f


# ---------- vérification d'un fichier serveur ----------
def verify_server_file(text, pub, last_seen_head=None, consistency=None):
    """Vérifie tout ; retourne la liste des états par créneau. Lève VerifyError sinon.
    last_seen_head : dernière tête déjà acceptée par ce vérificateur (anti-rejeu / anti-retour en arrière).
    consistency : preuve de cohérence (liste b64) de last_seen_head vers la tête du fichier."""
    try:
        f = loads_strict(text)
    except Exception as e:
        raise VerifyError("fichier illisible ou tronqué : %s" % type(e).__name__)
    for k in ("type", "server_id", "server_hash", "head", "head_sig", "cycles", "verdict"):
        if k not in f:
            raise VerifyError("champ manquant : %s" % k)
    if f["type"] != "COVERAGE_V1_SERVER" or server_hash(f["server_id"]) != f["server_hash"]:
        raise VerifyError("identité du serveur incohérente")
    head = f["head"]
    verify_head(pub, head, f["head_sig"])
    if last_seen_head is not None:
        if head["tree_size"] < last_seen_head["tree_size"]:
            raise VerifyError("tête rejouée : tree_size %d < %d déjà vu" % (head["tree_size"], last_seen_head["tree_size"]))
        if head["timestamp"] < last_seen_head["timestamp"]:
            raise VerifyError("tête rejouée : horodatage antérieur à la dernière tête vue")
        if not verify_consistency(last_seen_head["tree_size"], head["tree_size"], unb64(last_seen_head["root"]),
                                  unb64(head["root"]), [unb64(x) for x in (consistency or [])]):
            raise VerifyError("tête incohérente avec la dernière tête vue (fourche ou rejeu)")
    n, root = head["tree_size"], unb64(head["root"])
    if len(f["cycles"]) != n:
        raise VerifyError("fichier incomplet : %d créneaux pour une tête de %d" % (len(f["cycles"]), n))
    h, states = f["server_hash"], []
    for i, it in enumerate(f["cycles"]):
        d = it["cycle"]
        if d.get("slot") != i or d.get("type") != "COVERAGE_V1":
            raise VerifyError("créneau %d : ordre ou type invalide" % i)
        if not verify_inclusion(i, n, leaf_hash(cycle_leaf_bytes(d)), [unb64(x) for x in it["cycle_proof"]], root):
            raise VerifyError("créneau %d : feuille de cycle non incluse dans la tête" % i)
        er, cn = unb64(d["entries_root"]), d["n"]
        if d["state"] == "MISSED":
            states.append((d["slot_start"], "MISSED", None))
            continue
        if "entry" in it:
            e = it["entry"]
            if e["e"]["h"] != h:
                raise VerifyError("créneau %d : entrée d'un autre serveur" % i)
            if not verify_inclusion(e["index"], cn, leaf_hash(entry_bytes(e["e"])), [unb64(x) for x in e["proof"]], er):
                raise VerifyError("créneau %d : entrée altérée (preuve d'inclusion fausse)" % i)
            states.append((d["run_finished"], e["e"]["s"], e["e"].get("fp")))
        elif "absent" in it:
            nb = it["absent"]
            for e in nb:
                if not verify_inclusion(e["index"], cn, leaf_hash(entry_bytes(e["e"])), [unb64(x) for x in e["proof"]], er):
                    raise VerifyError("créneau %d : voisine altérée" % i)
            idx = [e["index"] for e in nb]
            ok = (len(nb) == 2 and idx[1] == idx[0] + 1 and nb[0]["e"]["h"] < h < nb[1]["e"]["h"]) or \
                 (len(nb) == 1 and ((idx[0] == 0 and h < nb[0]["e"]["h"]) or (idx[0] == cn - 1 and nb[0]["e"]["h"] < h))) or \
                 (len(nb) == 0 and cn == 0)
            if not ok:
                raise VerifyError("créneau %d : preuve d'absence invalide" % i)
            states.append((d["slot_start"], "ABSENT", None))
        else:
            raise VerifyError("créneau %d : ni entrée ni preuve d'absence" % i)
    if verdict_from_states(states) != f["verdict"]:
        raise VerifyError("verdict publié différent du verdict recalculé")
    return states


def states_of(f):
    out = []
    for it in f["cycles"]:
        d = it["cycle"]
        if d["state"] == "MISSED":
            out.append((d["slot_start"], "MISSED", None))
        elif "entry" in it:
            out.append((d["run_finished"], it["entry"]["e"]["s"], it["entry"]["e"].get("fp")))
        else:
            out.append((d["slot_start"], "ABSENT", None))
    return out


def verdict_from_states(states):
    """Règle stricte. states : [(date, état, fp)] dans l'ordre des créneaux ; date = fin du cycle (borne sûre :
    la sonde a eu lieu avant), ou début du créneau si MISSED/ABSENT."""
    if not states:
        return {"state": "UNKNOWN", "reason": "aucun créneau"}
    t, s, fp = states[-1]
    if s != "OBSERVED" or not fp:
        return {"state": "UNKNOWN", "reason": "dernier créneau %s : %s" % (t, s)}
    k = len(states) - 1
    while k > 0 and states[k - 1][1] == "OBSERVED" and states[k - 1][2] == fp:
        k -= 1
    before = None
    if k > 0:
        before = "fingerprint_changed" if states[k - 1][1] == "OBSERVED" else "gap:" + states[k - 1][1]
    return {"state": "UNCHANGED_SINCE", "since": states[k][0], "fp": fp, "cycles": len(states) - k,
            "before": before or "log_start"}


def query(states, date):
    """UNCHANGED_SINCE(date) ou UNKNOWN, selon la règle stricte."""
    v = verdict_from_states(states)
    if v["state"] == "UNCHANGED_SINCE" and date >= v["since"]:
        return {"state": "UNCHANGED_SINCE", "since": date}
    return {"state": "UNKNOWN", "reason": v.get("reason") or "trou ou changement avant %s" % v["since"]}
