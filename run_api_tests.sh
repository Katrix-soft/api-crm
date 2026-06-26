#!/bin/bash
# run_api_tests.sh — Ejecuta la suite de pruebas unitarias de Katrix ERP API

set -e

cd "$(dirname "$0")"

# 1. Activar virtualenv
if [ -d ".venv" ]; then
    source .venv/bin/activate
elif [ -d "venv" ]; then
    source venv/bin/activate
fi

# 2. Instalar dependencias si no están instaladas
echo "🔍 Verificando dependencias de prueba..."
pip install fastapi "uvicorn[standard]" "python-jose[cryptography]" passlib requests -q

# 3. Ejecutar pruebas
echo "🧪 Iniciando suite de pruebas unitarias..."
python test_api.py --test
