#!/bin/sh
# Contrôle COMPLET d'un bundle (complet ou démo), hors ligne. Usage : unshare -rn sh VERIFY_BUNDLE.sh <BUNDLE>
cd "$(dirname "$0")" && exec python3 -I -B -c 'import sys; sys.path.insert(0, "."); from exposure_scan.__main__ import main; sys.exit(main(["--verify-bundle", sys.argv[1], "--full"]))' "$1"
