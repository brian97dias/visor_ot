#!/usr/bin/env bash
# Acceso directo al gestor de estados recuperables del laboratorio VISOR OT.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/web_app/backend/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  echo "ERROR: no existe el entorno $PYTHON" >&2
  echo "Configura primero web_app/backend/.venv" >&2
  exit 1
fi
exec "$PYTHON" "$ROOT/visor_ot_simulacion_pcap/demo_entornos.py" "$@"
