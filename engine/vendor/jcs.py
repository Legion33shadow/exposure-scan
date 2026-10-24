"""JSON Canonicalization Scheme — RFC 8785 (JCS). Python 3, aucune dépendance.

  canonicalize(obj) -> bytes (UTF-8)

Règles (RFC 8785 §3.2) :
  - littéraux null / true / false ;
  - chaînes : sérialisation ECMAScript JSON.stringify — échappements \\b \\f \\n \\r \\t \\" \\\\ ; autres
    caractères < U+0020 en \\u00xx minuscule ; tout le reste tel quel en UTF-8 (pas d'échappement de « / » ni du non-ASCII) ;
    une moitié de paire de substitution isolée est refusée ;
  - nombres : IEEE 754 binaire64, forme ECMAScript Number.prototype.toString (le plus court aller-retour, exposant
    au-delà de 1e21 ou en deçà de 1e-6) ; -0 -> « 0 » ; NaN et ±Infinity refusés ;
    entiers Python : refusés au-delà de ±2**53 (au-delà, un double ne les représente plus exactement : on refuse
    plutôt que d'arrondir en silence) ;
  - objets : membres triés par les UNITÉS DE CODE UTF-16 des noms (et non par points de code, comme le fait
    Python `sort_keys`) ; noms en double impossibles en Python (dict) ;
  - aucun espace.
"""
import math

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
MAX_SAFE = 2 ** 53


class JCSError(ValueError):
    pass


def _str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise JCSError("moitié de paire de substitution isolée")
        if ch in _ESC:
            out.append(_ESC[ch])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s):
    return s.encode("utf-16-be")


def _num(x):
    if isinstance(x, bool):
        raise JCSError("booléen inattendu")
    if isinstance(x, int):
        if abs(x) > MAX_SAFE:
            raise JCSError("entier hors de ±2**53 : non représentable exactement en IEEE 754")
        return str(x)
    if not math.isfinite(x):
        raise JCSError("NaN/Infinity interdits")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))  # plus court aller-retour (comme ECMAScript), à reformater
    if "e" in r:
        mant, e = r.split("e")
        e = int(e)
    else:
        mant, e = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + e - lead_zeros          # position du point décimal : valeur = 0.d1d2… × 10^n
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        exp = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if exp >= 0 else "-") + str(abs(exp))
    return sign + s


def _ser(o, out):
    if o is None:
        out.append("null")
    elif o is True:
        out.append("true")
    elif o is False:
        out.append("false")
    elif isinstance(o, str):
        out.append(_str(o))
    elif isinstance(o, (int, float)):
        out.append(_num(o))
    elif isinstance(o, (list, tuple)):
        out.append("[")
        for i, v in enumerate(o):
            if i:
                out.append(",")
            _ser(v, out)
        out.append("]")
    elif isinstance(o, dict):
        if any(not isinstance(k, str) for k in o):
            raise JCSError("nom de membre non textuel")
        out.append("{")
        for i, k in enumerate(sorted(o, key=_utf16_key)):
            if i:
                out.append(",")
            out.append(_str(k))
            out.append(":")
            _ser(o[k], out)
        out.append("}")
    else:
        raise JCSError("type non JSON : %s" % type(o).__name__)


def canonicalize(obj):
    out = []
    _ser(obj, out)
    return "".join(out).encode("utf-8")


def loads_strict(text):
    """Analyse JSON qui refuse les noms en double (RFC 8785 §3.1 : I-JSON) et NaN/Infinity."""
    import json

    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise JCSError("nom de membre en double : %r" % k)
            d[k] = v
        return d

    def bad_const(c):
        raise JCSError("constante interdite : %s" % c)
    return json.loads(text, object_pairs_hook=hook, parse_constant=bad_const)
