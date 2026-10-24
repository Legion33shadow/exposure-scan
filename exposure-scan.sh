#!/bin/sh
# Lanceur isolé (python3 -I : ni PYTHONPATH, ni site utilisateur, ni répertoire courant). Mêmes options que
# « python3 -m exposure_scan ». Recommandé : unshare -rn sh exposure-scan.sh ...
D="$(cd "$(dirname "$0")" && pwd)"
exec python3 -I -B -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from exposure_scan.__main__ import main; sys.exit(main())' "$D" "$@"
