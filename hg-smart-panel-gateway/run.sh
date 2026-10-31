#!/usr/bin/env bash
set -e

echo "[*] ========================================================"
echo "[*] HG Smart Panel Gateway - Home Assistant Add-on v0.6.0"
echo "[*] Inicializando serviço nativo na porta 8090..."
echo "[*] ========================================================"

exec python3 /app/gateway.py
