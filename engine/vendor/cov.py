#!/usr/bin/env python3
"""COVERAGE_V1, disposition « sharded » (refonte 2026-10-17). Préproduction : rien de public.

Fichiers (racine = /tlog/v0/coverage/ une fois publié) :
  cycles/<i>.json        feuille du cycle i (immuable, écrite une fois)
  cycles/<i>/<pp>.json   tranche pp (00..ff = 2 premiers hex du server_hash) des entrées du cycle i, complète,
                         avec le chemin de sa feuille dans l'arbre des 256 tranches (immuable, écrite une fois)
  cycles/index.json      liste des hachés de feuilles de cycle (ajout seul ; revérifiable contre la tête)
  head.json              tête signée Ed25519 {tree_size, root, timestamp} (remplacée à chaque cycle)
  server/<hash>.json     ~400 octets : verdict + tree_size/root de la tête + proof_from (renvoi vers la plage de
                         cycles à lire). Taille bornée, indépendante du nombre de cycles.
Arbre du journal : feuille par cycle (RFC 6962). entries_root d'un cycle = racine RFC 6962 sur 256 feuilles de
tranche {slot, p, n, root(entrées de la tranche)} ; une tranche contient TOUTES les entrées de son préfixe, donc
l'absence d'un serveur se prouve en lisant sa seule tranche.
Règle stricte inchangée (merkle_v1.verdict_from_states) : UNCHANGED_SINCE(d) seulement si tous les créneaux
depuis d ont observé la même empreinte ; trou, non-observation ou changement -> UNKNOWN avant."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from merkle_v1 import (canonicalize, loads_strict, leaf_hash, mth, Tree, verify_inclusion, b64, unb64, server_hash,
                       entry_bytes, cycle_leaf_bytes, verdict_from_states, VerifyError, iso)

LOG_NAME = os.environ.get("COVERAGE_LOG_NAME", "legion-coverage-v1")   # prod depuis le 2026-10-17 (préprod : legion-coverage-v1-preprod)
LAYOUT = "sharded-256"
NSHARD = 256


def shard_of(h):
    return int(h[:2], 16)


def shard_leaf_bytes(slot, p, n, root_b64):
    return canonicalize({"type": "COVERAGE_V1_SHARD_LEAF", "slot": slot, "p": p, "n": n, "root": root_b64})


def build_cycle(i, slot_start, run):
    """run = None (MISSED) ou {"run_id", "run_finished", "entries": {server_hash: (state, fp, reason)}}.
    Retourne (cycle_doc, {p: shard_doc})."""
    if run is None:
        return ({"type": "COVERAGE_V1", "slot": i, "slot_start": iso(slot_start), "state": "MISSED", "run_id": None,
                 "run_finished": None, "n": 0, "entries_root": b64(mth([]))}, {})
    groups = [[] for _ in range(NSHARD)]
    for h, (s, fp, r) in sorted(run["entries"].items()):
        groups[shard_of(h)].append({"h": h, "s": s, "fp": fp, "r": r})
    roots = [b64(mth([leaf_hash(entry_bytes(e)) for e in g])) for g in groups]
    top = Tree([leaf_hash(shard_leaf_bytes(i, p, len(groups[p]), roots[p])) for p in range(NSHARD)])
    doc = {"type": "COVERAGE_V1", "slot": i, "slot_start": iso(slot_start), "state": "RAN", "run_id": run["run_id"],
           "run_finished": run["run_finished"], "n": len(run["entries"]), "entries_root": b64(top.root())}
    shards = {p: {"type": "COVERAGE_V1_SHARD", "slot": i, "p": p, "entries": groups[p],
                  "path": [b64(x) for x in top.path(p)]} for p in range(NSHARD)}
    return doc, shards


def sign_head(priv, head):
    return b64(priv.sign(canonicalize(head)))


def make_head(priv, leaves, timestamp):
    head = {"type": "COVERAGE_V1_HEAD", "layout": LAYOUT, "log": LOG_NAME, "tree_size": len(leaves),
            "root": b64(mth(leaves)), "timestamp": timestamp}
    return {"head": head, "sig": sign_head(priv, head)}


# ---------- état incrémental (local, non publié) ----------
def update_streaks(st, i, doc, run):
    """st = {"n": nb de cycles traités, "prev": état global du cycle précédent ("MISSED"/"RAN"),
    "srv": {h: [server_id, last_state, last_date, fp, k, since, before]}}. Équivaut à verdict_from_states
    sur l'historique complet (testé)."""
    assert st["n"] == i, "cycle %d attendu, %d reçu" % (st["n"], i)
    srv = st["srv"]
    ent = run["entries"] if run else {}
    for h, sid in (run.get("ids", {}) if run else {}).items():
        if h not in srv:   # nouveau serveur : absent (ou MISSED) dans tous les cycles précédents
            srv[h] = [sid, ("MISSED" if st["prev"] == "MISSED" else "ABSENT") if i else None, None, None, None, None, None]
    for h, rec in srv.items():
        prev_s, prev_fp = rec[1], rec[3]
        if doc["state"] == "MISSED":
            s, fp, d = "MISSED", None, doc["slot_start"]
        elif h in ent:
            s, fp, d = ent[h][0], ent[h][1], doc["run_finished"]
        else:
            s, fp, d = "ABSENT", None, doc["slot_start"]
        if s == "OBSERVED" and fp:
            if not (prev_s == "OBSERVED" and prev_fp == fp):
                rec[4], rec[5] = i, d
                rec[6] = "log_start" if i == 0 else ("fingerprint_changed" if prev_s == "OBSERVED" else "gap:" + prev_s)
        rec[1], rec[2], rec[3] = s, d, fp if s == "OBSERVED" else None
    st["n"], st["prev"] = i + 1, doc["state"]


def verdict_of(rec, n):
    _, s, d, fp, k, since, before = rec
    if s != "OBSERVED" or not fp:
        return {"state": "UNKNOWN", "reason": "dernier créneau %s : %s" % (d, s)}, n - 1
    return {"state": "UNCHANGED_SINCE", "since": since, "fp": fp, "cycles": n - k, "before": before}, max(k - 1, 0)


def server_doc(h, rec, head):
    v, frm = verdict_of(rec, head["tree_size"])
    return {"type": "COVERAGE_V1_SERVER", "server_id": rec[0], "server_hash": h, "tree_size": head["tree_size"],
            "root": head["root"], "verdict": v, "proof_from": frm}


# ---------- vérification (côté lecteur) ----------
SERVER_KEYS = {"type", "server_id", "server_hash", "tree_size", "root", "verdict", "proof_from"}


def _load(fetch, path):
    try:
        return loads_strict(fetch(path))
    except FileNotFoundError:
        raise VerifyError("fichier manquant : %s" % path)
    except Exception as e:
        raise VerifyError("fichier illisible ou tronqué : %s (%s)" % (path, type(e).__name__))


def verify_head_doc(hd, pub):
    from cryptography.exceptions import InvalidSignature
    head = hd.get("head") if isinstance(hd, dict) else None
    if not head or head.get("type") != "COVERAGE_V1_HEAD" or head.get("layout") != LAYOUT or head.get("log") != LOG_NAME:
        raise VerifyError("tête de type invalide")
    try:
        pub.verify(unb64(hd["sig"]), canonicalize(head))
    except (InvalidSignature, ValueError, KeyError) as e:
        raise VerifyError("signature de tête invalide") from e
    return head


def verify_shard(sd, i, p, entries_root):
    if sd.get("type") != "COVERAGE_V1_SHARD" or sd.get("slot") != i or sd.get("p") != p:
        raise VerifyError("cycle %d tranche %02x : en-tête de tranche invalide" % (i, p))
    es = sd["entries"]
    hs = [e["h"] for e in es]
    if hs != sorted(set(hs)) or any(shard_of(h) != p for h in hs):
        raise VerifyError("cycle %d tranche %02x : entrées non triées, en double ou hors préfixe" % (i, p))
    root = b64(mth([leaf_hash(entry_bytes(e)) for e in es]))
    if not verify_inclusion(p, NSHARD, leaf_hash(shard_leaf_bytes(i, p, len(es), root)), [unb64(x) for x in sd["path"]], unb64(entries_root)):
        raise VerifyError("cycle %d tranche %02x : tranche altérée ou incomplète (preuve d'inclusion fausse)" % (i, p))
    return {e["h"]: e for e in es}


def verify_server(text, fetch, pub, last_seen=None):
    """fetch(chemin relatif) -> texte. last_seen = {"tree_size","root","timestamp"} de la dernière tête acceptée.
    Retourne (verdict, états vérifiés, tête). Lève VerifyError sinon."""
    try:
        f = loads_strict(text)
    except Exception as e:
        raise VerifyError("fichier serveur illisible ou tronqué (%s)" % type(e).__name__)
    if not isinstance(f, dict) or set(f) != SERVER_KEYS or f["type"] != "COVERAGE_V1_SERVER":
        raise VerifyError("fichier serveur : champs invalides")
    if server_hash(f["server_id"]) != f["server_hash"]:
        raise VerifyError("identité du serveur incohérente")
    head = verify_head_doc(_load(fetch, "head.json"), pub)
    n = head["tree_size"]
    idx = _load(fetch, "cycles/index.json")
    leaves = [unb64(x) for x in idx.get("leaves", [])]
    if idx.get("type") != "COVERAGE_V1_INDEX" or len(leaves) != n or b64(mth(leaves)) != head["root"]:
        raise VerifyError("index des cycles incohérent avec la tête signée (tronqué ou altéré)")
    if last_seen is not None:
        m = last_seen["tree_size"]
        if n < m or head["timestamp"] < last_seen["timestamp"]:
            raise VerifyError("tête rejouée : plus ancienne que la dernière tête vue (%d < %d)" % (n, m))
        if b64(mth(leaves[:m])) != last_seen["root"]:
            raise VerifyError("fourche : la tête ne prolonge pas la dernière tête vue")
    if f["tree_size"] != n or f["root"] != head["root"]:
        raise VerifyError("fichier serveur lié à une autre tête (périmé ou rejoué)")
    a, h = f["proof_from"], f["server_hash"]
    if not (isinstance(a, int) and 0 <= a < n):
        raise VerifyError("proof_from hors bornes")
    states = []
    for i in range(a, n):
        cd = _load(fetch, "cycles/%d.json" % i)
        if cd.get("type") != "COVERAGE_V1" or cd.get("slot") != i or leaf_hash(cycle_leaf_bytes(cd)) != leaves[i]:
            raise VerifyError("cycle %d : feuille absente de la tête ou altérée" % i)
        if cd["state"] == "MISSED":
            states.append((cd["slot_start"], "MISSED", None))
            continue
        if cd["state"] != "RAN":
            raise VerifyError("cycle %d : état inconnu" % i)
        p = shard_of(h)
        ent = verify_shard(_load(fetch, "cycles/%d/%02x.json" % (i, p)), i, p, cd["entries_root"])
        e = ent.get(h)
        states.append((cd["run_finished"], e["s"], e.get("fp")) if e else (cd["slot_start"], "ABSENT", None))
    v = verdict_from_states(states)
    if a > 0 and v["state"] == "UNCHANGED_SINCE" and v["before"] == "log_start":
        raise VerifyError("plage de preuves trop courte : la série commence avant proof_from")
    if v != f["verdict"]:
        raise VerifyError("verdict publié différent du verdict recalculé")
    return v, states, head


def query(verdict, date):
    if verdict["state"] == "UNCHANGED_SINCE" and date >= verdict["since"]:
        return {"state": "UNCHANGED_SINCE", "since": date}
    return {"state": "UNKNOWN", "reason": verdict.get("reason") or "trou ou changement avant %s" % verdict["since"]}
