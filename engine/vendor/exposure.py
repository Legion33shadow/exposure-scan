#!/usr/bin/env python3
"""LEGION Change Exposure Engine, phase 1 (prototype isolé, hors ligne, déterministe).

derive(case_dir) lit case_dir/inputs.json et les artefacts qu'il référence, et produit le dossier d'exposition :
chronologie d'événements, fenêtres de changement, lacunes d'observation, corrélations, contradictions, et trois listes
séparées (faits établis, inférences, inconnues). Rien n'est lu ailleurs que dans case_dir ; aucun réseau.

Règles épistémiques (appliquées ici et revérifiées par verify_dossier.py, qui ré-exécute derive()) :
- un événement OBSERVED est adossé à un artefact inclus et à une vérification refaite ici (signature, inclusion, empreinte,
  présence textuelle) ; un événement INFERRED (EXPOSURE_POSSIBLE, IMPACT_UNKNOWN) cite les événements dont il dérive ;
- CLIENT_CONFIGURED n'implique pas TOOL_LIST_PRESENTED ; une présentation n'implique pas un appel ; un appel n'implique
  ni résultat ni usage ni impact. CALL_RESULT_CONFIRMED exige la réponse JSON-RPC brute ; un résumé rédigé par un agent
  n'en est pas une ;
- quand les sources ne relient pas un changement à un appel, la corrélation vaut UNKNOWN avec la donnée manquante ;
- une empreinte SHA-256 prouve l'identité d'un contenu, pas l'authenticité de sa source : seuls les artefacts signés
  (journal, couverture) sont marqués VERIFIED_SIGNED ; le reste est LOCAL_UNSIGNED.
Toute relation de provenance invalide (artefact manquant, rôle erroné, feuille inconnue, signature fausse, preuve qui
ne correspond pas) lève InvalidCase : aucun dossier n'est produit."""
import base64, hashlib, json, os, sys
from datetime import datetime, timezone

_H = os.path.dirname(os.path.abspath(__file__))
for _p in (_H, os.path.join(_H, "vendor")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import verify_tlog as VT  # noqa: E402  vérifieur public du journal (copie)
import cov as COV  # noqa: E402  vérifieur du registre COVERAGE_V1 (copie)
import merkle_v1 as MV  # noqa: E402

SCHEMA_IN = "legion-exposure-case/0.1"
SCHEMA_OUT = "legion-exposure-dossier/0.1"
EVENT_TYPES = ("CHANGE_OBSERVED", "CLIENT_CONFIGURED", "TOOL_LIST_PRESENTED", "CALL_OBSERVED", "CALL_RESULT_CONFIRMED",
               "EXPOSURE_POSSIBLE", "IMPACT_UNKNOWN")
OBSERVED_TYPES = EVENT_TYPES[:5]
LIMITS = [
    "Une empreinte SHA-256 identifie un contenu ; elle ne prouve pas qui l'a produit. Seuls le journal signé et le registre "
    "de couverture signé portent une signature vérifiée ici ; journaux clients, audit du proxy, fichiers et horodatages "
    "de fichiers sont locaux, non signés et modifiables.",
    "EXPOSURE_POSSIBLE signifie qu'une définition modifiée a été remise à un client ; cela ne prouve ni qu'un modèle l'a lue, "
    "ni qu'elle a influencé une décision.",
    "IMPACT_UNKNOWN est systématique : aucune source de ce dossier ne mesure un effet.",
    "Un changement observé n'est ni une attaque ni une intention ; un changement d'annotation déclarée ne prouve aucun "
    "changement de comportement.",
    "L'heure d'un changement n'est connue que dans une fenêtre : entre la dernière observation de l'ancienne version et la "
    "première observation de la nouvelle.",
]


class InvalidCase(Exception):
    pass


def _ts(s):
    if s is None:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _dump(o):
    return json.dumps(o, sort_keys=True, ensure_ascii=False, indent=1) + "\n"


class Case:
    def __init__(self, d):
        self.dir = os.path.abspath(d)
        p = os.path.join(self.dir, "inputs.json")
        if not os.path.isfile(p):
            raise InvalidCase("inputs.json absent")
        self.spec = json.load(open(p, encoding="utf-8"))
        if self.spec.get("schema") != SCHEMA_IN:
            raise InvalidCase("schéma d'entrée inconnu : %r" % self.spec.get("schema"))
        self.arts = self.spec.get("artifacts") or {}

    def art(self, aid, role=None):
        a = self.arts.get(aid)
        if a is None:
            raise InvalidCase("artefact non déclaré : %s" % aid)
        if role and a.get("role") != role:
            raise InvalidCase("artefact %s : rôle %r, attendu %r" % (aid, a.get("role"), role))
        rel = a["path"]
        full = os.path.normpath(os.path.join(self.dir, rel))
        if not full.startswith(self.dir + os.sep) or not os.path.isfile(full):
            raise InvalidCase("artefact manquant ou hors dossier : %s (%s)" % (aid, rel))
        return full

    def read(self, aid, role=None):
        return open(self.art(aid, role), "rb").read()

    def json(self, aid, role=None):
        try:
            return json.loads(self.read(aid, role))
        except ValueError as e:
            raise InvalidCase("artefact %s : JSON illisible (%s)" % (aid, e))

    def jsonl(self, aid, role=None):
        try:
            return [json.loads(l) for l in self.read(aid, role).decode("utf-8").splitlines() if l.strip()]
        except ValueError as e:
            raise InvalidCase("artefact %s : JSONL illisible (%s)" % (aid, e))


# ---------- sources signées ----------
def verify_signed_log(c):
    sl = c.spec.get("signed_log")
    if not sl:
        return None, {}, {}
    root = c.read(sl["root"], "tlog_root").decode().strip()
    try:
        keys = VT.load_keyring(c.read(sl["keyring"], "tlog_keyring").decode(), root)
    except Exception as e:
        raise InvalidCase("trousseau du journal refusé : %s" % e)
    sth = c.json(sl["sth"], "tlog_sth")
    if not VT.check_sth(sth, keys):
        raise InvalidCase("tête signée du journal : signature invalide")
    recs = {}
    for r in c.jsonl(sl["records"], "tlog_records"):
        recs[r["leaf_index"]] = r
    proofs = {}
    for aid in sl.get("proofs", []):
        p = c.json(aid, "tlog_proof")
        proofs[p["leaf_index"]] = (p, aid)
    report = {"sth": {"tree_size": sth["tree_head"]["tree_size"], "root_sha256": sth["tree_head"]["root_sha256"],
                      "timestamp": sth["tree_head"]["timestamp"], "signature": "VERIFIED"}, "leaves": {}}
    for li in sorted(recs):
        r = recs[li]
        integ, sig, err = VT.check_record(r, keys)
        if not (integ and sig):
            raise InvalidCase("feuille %d : intégrité %s, signature %s (%s)" % (li, integ, sig, err))
        if li not in proofs:
            raise InvalidCase("feuille %d : preuve d'inclusion absente" % li)
        if not VT.check_inclusion(r, proofs[li][0], sth):
            raise InvalidCase("feuille %d : preuve d'inclusion fausse pour la tête %d" % (li, sth["tree_head"]["tree_size"]))
        report["leaves"][str(li)] = {"record_signature": "VERIFIED", "inclusion": "VERIFIED (RFC 6962, tête %d)" % sth["tree_head"]["tree_size"],
                                      "observed_at": r["observed_at"], "server_id": r["server_id"],
                                      "tools_sha256": r["tools_fingerprint"]["sha256"]}
    return report, recs, sth


def verify_coverage(c, server_id):
    cv = c.spec.get("coverage")
    if not cv:
        return None, []
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(c.read(cv["pubkey"], "coverage_pubkey").decode().strip()))
    try:
        head = COV.verify_head_doc(c.json(cv["head"], "coverage_head"), pub)
    except MV.VerifyError as e:
        raise InvalidCase("couverture : %s" % e)
    idx = c.json(cv["index"], "coverage_index")
    leaves = [MV.unb64(x) for x in idx.get("leaves", [])]
    if idx.get("type") != "COVERAGE_V1_INDEX" or len(leaves) != head["tree_size"] or MV.b64(MV.mth(leaves)) != head["root"]:
        raise InvalidCase("couverture : index des cycles incohérent avec la tête signée")
    h = MV.server_hash(server_id)
    p = COV.shard_of(h)
    states = []
    for i in sorted(int(k) for k in cv["cycles"]):
        cd = c.json(cv["cycles"][str(i)], "coverage_cycle")
        if cd.get("slot") != i or i >= len(leaves) or MV.leaf_hash(MV.cycle_leaf_bytes(cd)) != leaves[i]:
            raise InvalidCase("couverture : cycle %d absent de la tête signée ou altéré" % i)
        if cd["state"] == "MISSED":
            states.append({"cycle": i, "slot_start": cd["slot_start"], "observed_by": None, "state": "MISSED", "fp": None, "reason": None})
            continue
        try:
            ent = COV.verify_shard(c.json(cv["shards"][str(i)], "coverage_shard"), i, p, cd["entries_root"])
        except (MV.VerifyError, KeyError) as e:
            raise InvalidCase("couverture : cycle %d tranche %02x : %s" % (i, p, e))
        e = ent.get(h)
        states.append({"cycle": i, "slot_start": cd["slot_start"], "observed_by": cd["run_finished"],
                       "state": e["s"] if e else "ABSENT", "fp": e.get("fp") if e else None, "reason": e.get("r") if e else None})
    return {"head": {"tree_size": head["tree_size"], "timestamp": head["timestamp"], "signature": "VERIFIED"},
            "server_hash": h, "cycles_verified": [s["cycle"] for s in states]}, states


# ---------- assertions observées ----------
def _per_tool(rec):
    return dict(rec["tools_fingerprint"]["per_tool_sha256"])


def _changed(rec):
    ch = rec.get("change") or {}
    return sorted(set(ch.get("added", [])) | set(ch.get("modified", [])))


def obs_change(c, a, recs):
    if "leaf_index" in a:
        li = a["leaf_index"]
        if li not in recs:
            raise InvalidCase("%s : feuille %s inconnue (absente des enregistrements vérifiés du dossier)" % (a["id"], li))
        r = recs[li]
        if r["server_id"] != c.spec["server_id"]:
            raise InvalidCase("%s : feuille %d concerne %s, pas %s" % (a["id"], li, r["server_id"], c.spec["server_id"]))
        prev = r.get("prev_leaf_index")
        if prev is not None and prev in recs and _ts(recs[prev]["observed_at"]) > _ts(r["observed_at"]):
            raise InvalidCase("%s : feuille précédente %d observée après la feuille %d" % (a["id"], prev, li))
        return {"id": a["id"], "type": "CHANGE_OBSERVED", "kind": "OBSERVED", "at": r["observed_at"],
                "at_source": "observed_at signé de la feuille %d (première observation de la nouvelle version, pas l'heure du changement)" % li,
                "client": None, "tools": _changed(r), "provenance": "signed_log", "validation": "VERIFIED_SIGNED",
                "evidence": [c.spec["signed_log"]["records"]] + [x for x in c.spec["signed_log"].get("proofs", []) if c.json(x)["leaf_index"] == li],
                "derived_from": [],
                "detail": {"leaf_index": li, "prev_leaf_index": prev, "change": r.get("change"), "change_kind": "tool_definition",
                           "removed": sorted((r.get("change") or {}).get("removed", []))}}
    line = _audit_line(c, a)
    hc = line.get("hint_changes") or []
    if not hc:
        raise InvalidCase("%s : la ligne d'audit citée ne contient aucun changement d'annotation" % a["id"])
    return {"id": a["id"], "type": "CHANGE_OBSERVED", "kind": "OBSERVED", "at": line["at"], "at_source": "horodatage de l'audit local du proxy",
            "client": None, "tools": sorted({h["tool"] for h in hc}), "provenance": "proxy_audit", "validation": "LOCAL_UNSIGNED",
            "evidence": [a["artifact"]], "derived_from": [],
            "detail": {"change_kind": "annotation", "hint_changes": hc, "fingerprint_changed_tools": line.get("changed_tools", []),
                       "behavior_change": "UNKNOWN (annotations déclarées seulement ; aucune source ne mesure le comportement)"}}


def _audit_line(c, a):
    lines = c.jsonl(a["artifact"], "proxy_audit")
    n = a.get("line")
    if not isinstance(n, int) or not 0 <= n < len(lines):
        raise InvalidCase("%s : ligne d'audit %r hors fichier" % (a["id"], n))
    line = lines[n]
    if line.get("server_id") != c.spec["server_id"]:
        raise InvalidCase("%s : ligne d'audit d'un autre serveur (%s)" % (a["id"], line.get("server_id")))
    return line


def obs_configured(c, a):
    cfg = c.json(a["artifact"], "client_config")
    s = (cfg.get("mcpServers") or {}).get(a["server_name"])
    if not isinstance(s, dict):
        raise InvalidCase("%s : serveur %r absent de la configuration citée" % (a["id"], a["server_name"]))
    return {"id": a["id"], "type": "CLIENT_CONFIGURED", "kind": "OBSERVED", "at": a.get("at"), "at_source": a.get("at_source") or "indisponible",
            "client": a["client"], "tools": [], "provenance": "client_config", "validation": "LOCAL_UNSIGNED", "evidence": [a["artifact"]],
            "derived_from": [], "detail": {"server_name": a["server_name"], "command": s.get("command"), "args": s.get("args"),
                                           "url": s.get("url"), "env_keys": sorted((s.get("env") or {}).keys())}}


def obs_presented(c, a, recs):
    if a["via"] == "proxy_audit":
        line = _audit_line(c, a)
        if not str(line.get("event", "")).startswith("tools/list"):
            raise InvalidCase("%s : la ligne d'audit n'est pas une liste d'outils" % a["id"])
        match = sorted(li for li, r in recs.items() if r["tools_fingerprint"]["sha256"] == line.get("live_tools_sha256"))
        per = _per_tool(recs[match[-1]]) if match else {}
        hidden = sorted(line.get("hidden_tools") or [])
        return {"id": a["id"], "type": "TOOL_LIST_PRESENTED", "kind": "OBSERVED", "at": line["at"], "at_source": "horodatage de l'audit local du proxy",
                "client": a.get("client"), "tools": sorted(set(per) - set(hidden)) if per else [], "provenance": "proxy_audit",
                "validation": "LOCAL_UNSIGNED; liste = feuille signée %s (empreinte recalculée)" % match[-1] if match else "LOCAL_UNSIGNED; liste sans feuille correspondante",
                "evidence": [a["artifact"]], "derived_from": [],
                "detail": {"live_tools_sha256": line.get("live_tools_sha256"), "matches_leaves": match, "per_tool_sha256": per,
                           "hidden_tools": hidden, "mode": line.get("mode"), "verdict": line.get("verdict"),
                           "client_attribution": a.get("client") or "UNKNOWN (l'audit du proxy n'enregistre pas l'identité du client)"}}
    if a["via"] == "client_tool_store":
        per, names = {}, []
        sk = a.get("schema_key", "inputSchema")
        for aid in a["artifacts"]:
            d = c.json(aid, "client_tool_store")
            t = {"name": d["name"], "description": d.get("description"), "inputSchema": d.get(sk)}
            t = {k: v for k, v in t.items() if v is not None}
            names.append(d["name"])
            per[d["name"]] = _sha(VT.canon_fp_for(a["algo"])(t))
        match = sorted(li for li, r in recs.items() if _per_tool(r) == per)
        per_leaf = {}
        for li, r in sorted(recs.items()):
            pr = _per_tool(r)
            per_leaf[str(li)] = sum(1 for n, h in per.items() if pr.get(n) == h)
        return {"id": a["id"], "type": "TOOL_LIST_PRESENTED", "kind": "OBSERVED", "at": a.get("at"), "at_source": a.get("at_source") or "indisponible",
                "client": a["client"], "tools": sorted(names), "provenance": "client_tool_store",
                "validation": ("LOCAL_UNSIGNED; contenu = feuille signée %s (%d/%d outils, empreintes recalculées)" % (match[-1], len(per), len(per))
                               if match else "LOCAL_UNSIGNED; aucune feuille signée identique"),
                "evidence": list(a["artifacts"]), "derived_from": [],
                "detail": {"algo": a["algo"], "schema_key": sk, "per_tool_sha256": per, "matches_leaves": match, "tools_matching_per_leaf": per_leaf}}
    raise InvalidCase("%s : via inconnu %r" % (a["id"], a.get("via")))


def obs_call(c, a):
    tr = c.jsonl(a["transcript"], "client_transcript")
    k = a["transcript_index"]
    if not isinstance(k, int) or not 0 <= k < len(tr):
        raise InvalidCase("%s : index de transcription hors fichier" % a["id"])
    uses = [x for x in tr[k]["message"]["content"] if x.get("type") == "tool_use"]
    ok = [u for u in uses if (u.get("input") or {}).get("toolName") == a["tool"] and (u.get("input") or {}).get("arguments") == a["arguments"]]
    if not ok:
        raise InvalidCase("%s : la transcription ne contient pas cet appel (%s, mêmes arguments)" % (a["id"], a["tool"]))
    ev = [a["transcript"]]
    if a.get("log"):
        txt = c.read(a["log"], "client_log").decode("utf-8", "replace")
        miss = [s for s in a.get("log_contains", []) if s not in txt]
        if miss:
            raise InvalidCase("%s : chaînes absentes du journal client : %s" % (a["id"], miss))
        ev.append(a["log"])
    return {"id": a["id"], "type": "CALL_OBSERVED", "kind": "OBSERVED", "at": a.get("at"), "at_source": a.get("at_source") or "indisponible",
            "client": a["client"], "tools": [a["tool"]], "provenance": "client_transcript+client_log" if a.get("log") else "client_transcript",
            "validation": "LOCAL_UNSIGNED; appel retrouvé dans la transcription (outil et arguments identiques)",
            "evidence": ev, "derived_from": [], "detail": {"arguments": a["arguments"], "server": ok[0]["input"].get("server"),
                                                           "log_contains": a.get("log_contains", [])}}


def obs_result(c, a, calls):
    if a["call"] not in calls:
        raise InvalidCase("%s : appel %s inconnu" % (a["id"], a["call"]))
    r = c.json(a["artifact"], "raw_call_result")
    if r.get("jsonrpc") != "2.0" or "result" not in r or not isinstance(r["result"].get("content"), list):
        raise InvalidCase("%s : l'artefact n'est pas une réponse JSON-RPC tools/call brute" % a["id"])
    return {"id": a["id"], "type": "CALL_RESULT_CONFIRMED", "kind": "OBSERVED", "at": a.get("at"), "at_source": a.get("at_source") or "indisponible",
            "client": calls[a["call"]]["client"], "tools": calls[a["call"]]["tools"], "provenance": "raw_call_result", "validation": "LOCAL_UNSIGNED; réponse brute présente",
            "evidence": [a["artifact"]], "derived_from": [a["call"]],
            "detail": {"is_error": bool(r["result"].get("isError")), "content_sha256": _sha(json.dumps(r["result"], sort_keys=True).encode())}}


# ---------- règles ----------
def change_windows(changes, recs, cov_report, states):
    out, gaps = [], []
    for ch in changes:
        if ch["detail"]["change_kind"] != "tool_definition":
            continue
        r = recs[ch["detail"]["leaf_index"]]
        new_fp, upper = r["tools_fingerprint"]["sha256"], _ts(r["observed_at"])
        prev = ch["detail"]["prev_leaf_index"]
        prev_fp = recs[prev]["tools_fingerprint"]["sha256"] if prev in recs else None
        w = {"change": ch["id"], "upper_bound": r["observed_at"], "upper_source": "première observation signée (feuille %d)" % r["leaf_index"]}
        earlier_new = [s for s in states if s["fp"] == new_fp and s["observed_by"] and _ts(s["observed_by"]) < upper]
        if earlier_new:
            s = min(earlier_new, key=lambda s: _ts(s["observed_by"]))
            upper = _ts(s["observed_by"])
            w.update(upper_bound=s["observed_by"], upper_source="couverture signée, cycle %d" % s["cycle"])
        old = [s for s in states if prev_fp and s["fp"] == prev_fp and s["observed_by"] and _ts(s["observed_by"]) <= upper]
        if old:
            s = max(old, key=lambda s: _ts(s["slot_start"]))
            lower = s["slot_start"]
            w.update(lower_bound=lower, lower_source="couverture signée, cycle %d : ancienne version observée entre %s et %s ; borne prudente = début du créneau"
                     % (s["cycle"], s["slot_start"], s["observed_by"]))
        elif prev in recs:
            lower = recs[prev]["observed_at"]
            w.update(lower_bound=lower, lower_source="observed_at signé de la feuille précédente %d (aucune observation intermédiaire dans le dossier)" % prev)
        else:
            lower = None
            w.update(lower_bound=None, lower_source="UNKNOWN : feuille précédente absente du dossier")
        w["exact_change_time"] = "UNKNOWN"
        out.append(w)
        if lower is None:
            continue
        lo = _ts(lower)
        inside = [s for s in states if lo <= _ts(s["slot_start"]) <= upper]
        w["observations_inside"] = [{"cycle": s["cycle"], "slot_start": s["slot_start"], "state": s["state"],
                                     "version": "ancienne" if s["fp"] == prev_fp else "nouvelle" if s["fp"] == new_fp else None} for s in inside]
        for s in inside:
            if s["state"] != "OBSERVED":
                gaps.append({"change": ch["id"], "from": s["slot_start"], "to": s["observed_by"], "source": "couverture signée, cycle %d" % s["cycle"],
                             "state": s["state"], "reason": s["reason"]})
        if cov_report is None:
            gaps.append({"change": ch["id"], "from": lower, "to": w["upper_bound"], "source": "aucune donnée d'observation dans le dossier",
                         "state": "NO_DATA", "reason": None})
        else:
            ht = _ts(cov_report["head"]["timestamp"])
            if ht < upper:
                gaps.append({"change": ch["id"], "from": max(ht, lo).strftime("%Y-%m-%dT%H:%M:%SZ"), "to": w["upper_bound"],
                             "source": "après la tête de couverture signée (%s)" % cov_report["head"]["timestamp"], "state": "NO_DATA", "reason": None})
    return out, gaps


def derive(case_dir):
    c = Case(case_dir)
    sid = c.spec["server_id"]
    log_report, recs, _ = verify_signed_log(c)
    cov_report, states = verify_coverage(c, sid)
    ev, calls = [], {}
    for a in c.spec.get("assertions", []):
        t = a.get("type")
        if t not in OBSERVED_TYPES:
            raise InvalidCase("%s : type d'assertion %r interdit (les inférences sont dérivées, jamais déclarées)" % (a.get("id"), t))
        if any(e["id"] == a["id"] for e in ev):
            raise InvalidCase("identifiant en double : %s" % a["id"])
        if t == "CHANGE_OBSERVED":
            ev.append(obs_change(c, a, recs))
        elif t == "CLIENT_CONFIGURED":
            ev.append(obs_configured(c, a))
        elif t == "TOOL_LIST_PRESENTED":
            ev.append(obs_presented(c, a, recs))
        elif t == "CALL_OBSERVED":
            e = obs_call(c, a); ev.append(e); calls[e["id"]] = e
        elif t == "CALL_RESULT_CONFIRMED":
            ev.append(obs_result(c, a, calls))
    changes = [e for e in ev if e["type"] == "CHANGE_OBSERVED"]
    pres = [e for e in ev if e["type"] == "TOOL_LIST_PRESENTED"]
    results = {e["derived_from"][0]: e for e in ev if e["type"] == "CALL_RESULT_CONFIRMED"}
    windows, gaps = change_windows(changes, recs, cov_report, states)
    wmap = {w["change"]: w for w in windows}
    contradictions, inferences, unknowns, corr = [], [], [], []

    # contradictions temporelles
    for r in results.values():
        call = calls[r["derived_from"][0]]
        if r["at"] and call["at"] and _ts(r["at"]) < _ts(call["at"]):
            contradictions.append({"events": [call["id"], r["id"]], "rule": "résultat horodaté avant son appel"})
    for p in pres:
        for ch in changes:
            w = wmap.get(ch["id"])
            if not (p["at"] and w and w.get("lower_bound")) or ch["detail"]["change_kind"] != "tool_definition":
                continue
            newv = _per_tool(recs[ch["detail"]["leaf_index"]])
            if ch["tools"] and all(p["detail"]["per_tool_sha256"].get(t) == newv.get(t) for t in ch["tools"] if t in p["detail"]["per_tool_sha256"]) \
                    and any(t in p["detail"]["per_tool_sha256"] for t in ch["tools"]) and _ts(p["at"]) < _ts(w["lower_bound"]):
                contradictions.append({"events": [ch["id"], p["id"]], "rule": "nouvelle version présentée avant la borne basse de sa fenêtre de changement"})

    # expositions possibles
    exposures = []
    for ch in changes:
        hit = False
        for p in pres:
            if ch["detail"]["change_kind"] == "tool_definition":
                newv = _per_tool(recs[ch["detail"]["leaf_index"]])
                tools = sorted(t for t in ch["tools"] if t in p["tools"] and p["detail"]["per_tool_sha256"].get(t) == newv.get(t))
            else:
                if not p["at"] or _ts(p["at"]) < _ts(ch["at"]):
                    continue
                tools = sorted(t for t in ch["tools"] if t in p["tools"])   # p["tools"] exclut les outils masqués (mode block)
            if not tools:
                continue
            hit = True
            x = {"id": "X-%d" % (len(exposures) + 1), "type": "EXPOSURE_POSSIBLE", "kind": "INFERRED", "at": p["at"], "at_source": "heure de la présentation %s" % p["id"],
                 "client": p["client"], "tools": tools, "provenance": "derived", "validation": "INFERENCE",
                 "evidence": [], "derived_from": [ch["id"], p["id"]],
                 "detail": {"basis": ("définition post-changement (empreinte signée de la feuille %d) remise au client" % ch["detail"]["leaf_index"])
                            if ch["detail"]["change_kind"] == "tool_definition" else "annotations modifiées remises au client (liste non masquée)",
                            "not_proven": "lecture par un modèle, influence sur une décision, appel de ces outils"}}
            exposures.append(x)
        if not hit:
            unknowns.append({"about": ch["id"], "statement": "aucune preuve de présentation de la nouvelle version à un client dans ce dossier",
                             "missing": "audit de proxy ou stockage d'outils côté client couvrant une connexion postérieure au changement"})
    impacts = [{"id": "I-%d" % (i + 1), "type": "IMPACT_UNKNOWN", "kind": "INFERRED", "at": None, "at_source": "sans objet", "client": x["client"],
                "tools": x["tools"], "provenance": "derived", "validation": "UNKNOWN", "evidence": [], "derived_from": [x["id"]],
                "detail": {"reason": "aucune source ne mesure l'effet d'une définition présentée sur la sortie ou les actions de l'agent"}}
               for i, x in enumerate(exposures)]

    # corrélations changement <-> appel
    for call in calls.values():
        t = call["tools"][0]
        cp = [p for p in pres if p["client"] == call["client"] and t in p["tools"]]
        before = [p for p in cp if p["at"] and call["at"] and _ts(p["at"]) <= _ts(call["at"])]
        if cp and not before and all(p["at"] and call["at"] for p in cp):
            contradictions.append({"events": [p["id"] for p in cp] + [call["id"]], "rule": "appel horodaté avant toute présentation de l'outil à ce client"})
        for ch in changes:
            base = {"change": ch["id"], "call": call["id"], "client": call["client"], "tool": t}
            bad = [k for k in contradictions if call["id"] in k["events"] or ch["id"] in k["events"]]
            if bad:
                corr.append(dict(base, status="UNKNOWN", reason="contradiction temporelle : %s" % "; ".join(k["rule"] for k in bad)))
                continue
            if ch["detail"]["change_kind"] == "annotation":
                if t in ch["tools"] and before:
                    corr.append(dict(base, status="CORRELATED", reason="appel d'un outil dont les annotations modifiées ont été présentées à ce client avant l'appel ; comportement : UNKNOWN"))
                elif t not in ch["tools"]:
                    corr.append(dict(base, status="NOT_CORRELATED", reason="l'outil appelé n'est pas concerné par le changement d'annotations"))
                else:
                    corr.append(dict(base, status="UNKNOWN", reason="aucune présentation horodatée de ce client avant l'appel"))
                continue
            li, prev = ch["detail"]["leaf_index"], ch["detail"]["prev_leaf_index"]
            if t not in ch["tools"]:
                if prev in recs and _per_tool(recs[prev]).get(t) == _per_tool(recs[li]).get(t) is not None:
                    corr.append(dict(base, status="NOT_CORRELATED", reason="définition de %s identique dans les feuilles signées %d et %d" % (t, prev, li)))
                else:
                    corr.append(dict(base, status="UNKNOWN", reason="définition précédente de %s non vérifiable dans ce dossier" % t))
                continue
            newh = _per_tool(recs[li]).get(t)
            seen = [p for p in before if p["detail"]["per_tool_sha256"].get(t) == newh]
            if seen:
                corr.append(dict(base, status="CORRELATED", reason="appel de %s après présentation à ce client de sa définition post-changement (%s)" % (t, ", ".join(p["id"] for p in seen))))
            else:
                corr.append(dict(base, status="UNKNOWN", reason="aucune preuve que la version appelée soit la version post-changement",
                                 missing="présentation horodatée de la définition de %s à ce client avant l'appel" % t))
        if call["id"] not in results:
            unknowns.append({"about": call["id"], "statement": "résultat de l'appel non confirmé",
                             "missing": "réponse JSON-RPC tools/call brute (ni le client ni le proxy ne l'ont conservée)"})

    # inférences de rattachement (proximité temporelle seulement)
    for p in pres:
        if p["client"] is None:
            for q in pres:
                if q["client"] and q["at"] and p["at"] and abs((_ts(q["at"]) - _ts(p["at"])).total_seconds()) <= 5 \
                        and set(p["detail"]["matches_leaves"]) & set(q["detail"]["matches_leaves"]):
                    inferences.append({"about": [p["id"], q["id"]], "statement": "la présentation %s (client non enregistré par le proxy) est probablement celle reçue par %s : même version signée, écart de %.3f s"
                                       % (p["id"], q["client"], abs((_ts(q["at"]) - _ts(p["at"])).total_seconds())), "basis": "proximité temporelle", "proven": False})
    for a in c.spec.get("replays", []):
        c.read(a["artifact"], "replay_comparison")
        inferences.append({"about": [a["call"]], "statement": a["statement"], "basis": "comparaison de réponses (artefact %s)" % a["artifact"], "proven": False,
                           "limits": a["limits"]})
    for x in exposures:
        inferences.append({"about": [x["id"]], "statement": "exposition possible de %s à %s" % (x["client"] or "un client non identifié", ", ".join(x["tools"])),
                           "basis": x["detail"]["basis"], "proven": False})
    for ch in changes:
        if ch["detail"]["change_kind"] == "annotation":
            unknowns.append({"about": ch["id"], "statement": "changement de comportement de %s" % ", ".join(ch["tools"]),
                             "missing": "observation du comportement (appels et résultats avant/après) ; les annotations sont déclaratives"})
    for w in windows:
        unknowns.append({"about": w["change"], "statement": "heure exacte du changement",
                         "missing": "observation entre %s et %s" % (_u(w.get("lower_bound")), w["upper_bound"])})
    for i in impacts:
        unknowns.append({"about": i["id"], "statement": "impact", "missing": i["detail"]["reason"]})

    events = ev + exposures + impacts
    events.sort(key=lambda e: (e["at"] is None, _ts(e["at"]) if e["at"] else datetime.min.replace(tzinfo=timezone.utc), e["id"]))
    ids = {e["id"] for e in events}
    for e in events:
        for d in e["derived_from"]:
            if d not in ids:
                raise InvalidCase("%s dérive de %s, inconnu" % (e["id"], d))
        for aid in e["evidence"]:
            c.art(aid)
        if e["type"] in OBSERVED_TYPES and (e["kind"] != "OBSERVED" or not e["evidence"]):
            raise InvalidCase("%s : événement observé sans preuve" % e["id"])
    facts = [{"about": e["id"], "statement": "%s %s%s%s" % (e["type"], ", ".join(e["tools"]) if e["tools"] else "", " — client %s" % e["client"] if e["client"] else "",
                                                            " — %s" % e["at"] if e["at"] else " — heure indisponible"),
              "validation": e["validation"], "provenance": e["provenance"]} for e in events if e["kind"] == "OBSERVED"]
    return {"schema": SCHEMA_OUT, "case_id": c.spec["case_id"], "server_id": sid,
            "status": "CONTRADICTION" if contradictions else "CONSISTENT",
            "events": events, "change_windows": windows, "gaps": gaps, "correlations": corr, "contradictions": contradictions,
            "facts": facts, "inferences": inferences, "unknowns": unknowns,
            "checks": {"signed_log": log_report, "coverage": cov_report,
                       "artifacts": {aid: {"role": a["role"], "provenance": a.get("provenance"), "sha256": _sha(c.read(aid))} for aid, a in sorted(c.arts.items())}},
            "limits": LIMITS}


def _sec(title, lines, empty):
    return ["", "## " + title, ""] + (lines or ["- " + empty])


def _u(x):
    return "UNKNOWN" if x is None else x


def render(d):
    L = ["# Dossier d'exposition — %s" % d["case_id"], "", "Serveur : `%s` · statut : **%s** · schéma %s" % (d["server_id"], d["status"], d["schema"]), ""]
    L += ["## Chronologie", "", "| heure (UTC) | événement | nature | client | outils | provenance / validation | dérive de |", "|---|---|---|---|---|---|---|"]
    for e in d["events"]:
        L.append("| %s | %s `%s` | %s | %s | %s | %s · %s | %s |" % (e["at"] or "—", e["type"], e["id"], e["kind"], e["client"] or "—",
                                                               ", ".join(e["tools"]) or "—", e["provenance"], e["validation"], ", ".join(e["derived_from"]) or "—"))
    L += ["", "## Fenêtres de changement", ""]
    for w in d["change_windows"]:
        L.append("- `%s` : entre %s (%s) et %s (%s) ; heure exacte : %s ; observations dans la fenêtre : %s" % (
            w["change"], _u(w.get("lower_bound")), w["lower_source"], w["upper_bound"], w["upper_source"], w["exact_change_time"],
            ", ".join("cycle %d %s%s" % (o["cycle"], o["state"], " (%s version)" % o["version"] if o["version"] else "") for o in w.get("observations_inside", [])) or "aucune"))
    L += _sec("Intervalles non observés", ["- `%s` : %s → %s · %s · %s%s" % (g["change"], _u(g["from"]), _u(g["to"]), g["state"], g["source"], " (%s)" % g["reason"] if g["reason"] else "")
                                           for g in d["gaps"]], "aucun")
    L += _sec("Corrélations changement ↔ appel", ["- `%s` ↔ `%s` (%s, %s) : **%s** — %s%s" % (k["change"], k["call"], k["client"], k["tool"], k["status"], k["reason"],
                                                   " — manque : %s" % k["missing"] if k.get("missing") else "") for k in d["correlations"]], "aucun appel")
    L += _sec("Contradictions", ["- %s : %s" % (", ".join(k["events"]), k["rule"]) for k in d["contradictions"]], "aucune")
    L += _sec("Faits établis", ["- `%s` %s · %s" % (f["about"], f["statement"], f["validation"]) for f in d["facts"]], "aucun")
    L += _sec("Inférences (non prouvées)", ["- %s — base : %s%s" % (i["statement"], i["basis"], " — limites : %s" % i["limits"] if i.get("limits") else "")
                                            for i in d["inferences"]], "aucune")
    L += _sec("Inconnues", ["- `%s` %s — manque : %s" % (u["about"], u["statement"], u["missing"]) for u in d["unknowns"]], "aucune")
    L += ["", "## Vérifications refaites", ""]
    if d["checks"]["signed_log"]:
        s = d["checks"]["signed_log"]
        L.append("- journal : tête %d (%s) signature %s ; feuilles %s : signature + inclusion vérifiées" % (s["sth"]["tree_size"], s["sth"]["timestamp"], s["sth"]["signature"], ", ".join(sorted(s["leaves"], key=int))))
    if d["checks"]["coverage"]:
        s = d["checks"]["coverage"]
        L.append("- couverture : tête %d (%s) signature %s ; cycles vérifiés %s" % (s["head"]["tree_size"], s["head"]["timestamp"], s["head"]["signature"], s["cycles_verified"]))
    L += ["- artefacts : %d, empreintes dans MANIFEST.json" % len(d["checks"]["artifacts"]), "", "## Limites", ""] + ["- " + x for x in d["limits"]]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.stdout.write(_dump(derive(sys.argv[1])))
