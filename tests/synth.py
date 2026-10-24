#!/usr/bin/env python3
"""Bundle SYNTHÉTIQUE signé par des clés de TEST générées à la volée (jamais la clé LEGION ; refusé sans --test-key).
Serveur io.example/demo, outils a et b :
  feuille 0  2026-10-09T00:00Z  a=A1 b=B1 (ajout)        feuille 1  2026-10-09T01:00Z  io.example/other (remplissage)
  feuille 2  2026-10-12T06:00Z  a=A2 (modifié), b=B1
Couverture : créneaux de 12 h depuis 2026-10-10T00:00Z ; 0,1,2,4 OBSERVED(feuille 0) ; 3 MISSED ; 5 NOT_OBSERVED ;
6,7 OBSERVED(feuille 2). Usage : synth.py OUT_BUNDLE (renvoie les définitions utilisées, pour la fixture)."""
import base64, hashlib, json, os, sys
from datetime import datetime, timedelta, timezone

PK = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(PK, "cli"))
from exposure_scan import load_engine  # noqa: E402
from exposure_scan.bundle import write_manifest  # noqa: E402

ALGO = "sha256(JCS-RFC8785(sorted[{name,description,inputSchema}]))/v2"
DEFS = {
    "A1": {"name": "a", "description": "DESC-MARKER-a1 version 1", "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}}},
    "A2": {"name": "a", "description": "DESC-MARKER-a2 version 2", "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}, "y": {"type": "number"}}}},
    "B1": {"name": "b", "description": "DESC-MARKER-b1", "inputSchema": {"type": "object"}},
    "O1": {"name": "o", "description": "other", "inputSchema": {"type": "object"}},
}


def b64(b):
    return base64.b64encode(b).decode()


def make(out, seed=b"test-seed-1"):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    eng, R, S, B, VT, COV, MV = load_engine()
    raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    root = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed + b"root").digest())
    covk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed + b"cov").digest())
    pub = b64(raw(root)); pin = VT.key_pin(pub)
    os.makedirs(os.path.join(out, "tlog", "proofs")); os.makedirs(os.path.join(out, "coverage", "cycles"))
    open(os.path.join(out, "tlog", "legion_root.b64"), "w").write(pub + "\n")
    body = {"type": "key_register", "key_id": "k1:" + pin[:32], "alg": "Ed25519", "public_key_b64": pub, "issuer_claimed": "TEST (synthétique)",
            "valid_from": "2026-10-01T00:00:00+00:00", "prev_hash": "0" * 64}
    c = VT.canon(body)
    open(os.path.join(out, "tlog", "keyring.jsonl"), "w").write(json.dumps(dict(body, hash=hashlib.sha256(c).hexdigest(), self_sig=b64(root.sign(c)))) + "\n")
    h = {k: R.tool_hashes(d["name"], d["description"], d["inputSchema"])[ALGO] for k, d in DEFS.items()}

    def rec(i, sid, at, prev, tools, change):
        per = sorted([t, h[v]] for t, v in tools.items())
        fp = {"algo": ALGO, "per_tool_sha256": per, "sha256": hashlib.sha256(json.dumps(per).encode()).hexdigest(), "tool_count": len(per)}
        r = {"schema": VT.RECORD_SCHEMA, "leaf_index": i, "server_id": sid, "observed_at": at, "prev_leaf_index": prev,
             "tools_fingerprint": fp, "change": change, "claim_state": "unclaimed", "key_id": pin}
        r["signature_ed25519"] = b64(root.sign(VT.canon(r)))
        return r
    recs = [rec(0, "io.example/demo", "2026-10-09T00:00:00Z", None, {"a": "A1", "b": "B1"}, {"added": ["a", "b"], "modified": [], "removed": []}),
            rec(1, "io.example/other", "2026-10-09T01:00:00Z", None, {"o": "O1"}, {"added": ["o"], "modified": [], "removed": []}),
            rec(2, "io.example/demo", "2026-10-12T06:00:00Z", 0, {"a": "A2", "b": "B1"}, {"added": [], "modified": ["a"], "removed": []})]
    with open(os.path.join(out, "tlog", "records.jsonl"), "w") as f:
        for r in recs:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    hs = [VT.leaf_hash(VT.canon(r)) for r in recs]
    head = {"schema": VT.STH_SCHEMA, "tree_size": len(recs), "root_sha256": B.mth(hs).hex(), "timestamp": "2026-10-13T14:00:00Z", "issuer_pin_sha256": pin}
    json.dump({"tree_head": head, "signature_ed25519": b64(root.sign(VT.canon(head)))}, open(os.path.join(out, "tlog", "sth_%d.json" % len(recs)), "w"))
    for li in range(len(recs)):
        json.dump({"leaf_index": li, "tree_size": len(recs), "audit_path": [x.hex() for x in B.path(li, hs)]}, open(os.path.join(out, "tlog", "proofs", "LCI-%d.json" % li), "w"))
    demo, other = MV.server_hash("io.example/demo"), MV.server_hash("io.example/other")
    fp0, fp2 = recs[0]["tools_fingerprint"]["sha256"], recs[2]["tools_fingerprint"]["sha256"]
    t0 = datetime(2026, 10, 10, tzinfo=timezone.utc)
    plan = {0: ("OBSERVED", fp0, None), 1: ("OBSERVED", fp0, None), 2: ("OBSERVED", fp0, None), 3: None, 4: ("OBSERVED", fp0, None),
            5: ("NOT_OBSERVED", None, "not_probed"), 6: ("OBSERVED", fp2, None), 7: ("OBSERVED", fp2, None)}
    leaves = []
    for i in range(8):
        st = t0 + timedelta(hours=12 * i)
        run = None if plan[i] is None else {"run_id": MV.iso(st + timedelta(minutes=5)), "run_finished": MV.iso(st + timedelta(minutes=30)),
                                            "entries": {demo: plan[i], other: ("OBSERVED", recs[1]["tools_fingerprint"]["sha256"], None)}}
        doc, shards = COV.build_cycle(i, st, run)
        json.dump(doc, open(os.path.join(out, "coverage", "cycles", "%d.json" % i), "w"))
        if shards:
            os.makedirs(os.path.join(out, "coverage", "cycles", str(i)))
            for p, sd in shards.items():
                json.dump(sd, open(os.path.join(out, "coverage", "cycles", str(i), "%02x.json" % p), "w"))
        leaves.append(MV.leaf_hash(MV.cycle_leaf_bytes(doc)))
    json.dump({"type": "COVERAGE_V1_INDEX", "leaves": [MV.b64(x) for x in leaves]}, open(os.path.join(out, "coverage", "cycles", "index.json"), "w"))
    json.dump(COV.make_head(covk, leaves, "2026-10-13T13:00:00Z"), open(os.path.join(out, "coverage", "head.json"), "w"))
    open(os.path.join(out, "coverage", "pubkey.txt"), "w").write(b64(raw(covk)) + "\n")
    return write_manifest(out)


if __name__ == "__main__":
    print(make(sys.argv[1]))
