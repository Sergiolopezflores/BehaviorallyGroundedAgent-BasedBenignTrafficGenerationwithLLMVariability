#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agentegameravanzado.py — Orquestador de Agentes TFM

Lanza de forma secuencial el agente web (agentev7.py) y el agente gamer
(agentegamer3.py) en turnos configurables. Los agentes no pueden correr
en paralelo porque el gamer usa pyautogui para controlar el teclado/ratón.

Modos de funcionamiento:
  - ciclico      : alterna entre agentes N veces según ORDEN y CICLOS
  - secuencia    : ejecuta la lista SECUENCIA definida en el script
  - tiempo_total : define duración total y % de tráfico por agente

Uso:
  python agentegameravanzado.py
  MODO=tiempo_total TIEMPO_TOTAL_S=3600 PORCENTAJE_WEB=60 python agentegameravanzado.py
  MODO=tiempo_total TIEMPO_TOTAL_S=7200 PORCENTAJE_WEB=40 TURNO_S=900 python agentegameravanzado.py
  CICLOS=4 DURACION_WEB_S=1800 python agentegameravanzado.py

Requisitos:
  - agentev7.py y agentegamer3.py en el mismo directorio
  - Variables de entorno del agente web configuradas (.env o shell)
"""

import os
import sys
import time
import subprocess
import signal
from datetime import datetime, timedelta

# ══════════════════════════════════════════════════════════
#  CONFIGURACIÓN
# ══════════════════════════════════════════════════════════

# ── Modo de operación ─────────────────────────────────────
# "ciclico"     : alterna entre los agentes de ORDEN, CICLOS veces
# "secuencia"   : ejecuta la lista SECUENCIA en orden
# "tiempo_total": define duración total y % de tráfico por agente
MODO = os.environ.get("MODO", "ciclico")

# ── Modo cíclico ──────────────────────────────────────────
CICLOS = int(os.environ.get("CICLOS", "2"))
ORDEN  = os.environ.get("ORDEN", "web,gamer").split(",")

DURACION_WEB_S   = int(os.environ.get("DURACION_WEB_S",   "1800"))  # 30 min por turno web
DURACION_GAMER_S = int(os.environ.get("DURACION_GAMER_S", "1800"))  # 30 min por turno gamer

# ── Pausa entre agentes ───────────────────────────────────
PAUSA_ENTRE_S = int(os.environ.get("PAUSA_ENTRE_S", "30"))

# ── Modo secuencia ────────────────────────────────────────
# Lista de turnos: {"agente": "web"|"gamer", "duracion": segundos}
SECUENCIA = [
    {"agente": "web",   "duracion": 2700},   # 45 min web
    {"agente": "gamer", "duracion": 1800},   # 30 min gamer
    {"agente": "web",   "duracion": 1800},   # 30 min web
    {"agente": "gamer", "duracion": 1800},   # 30 min gamer
]

# ── Modo tiempo_total ─────────────────────────────────────
# Define la duración total de la sesión y el porcentaje de tiempo
# que genera cada agente. Los turnos se reparten automáticamente.
#
# Ejemplo: TIEMPO_TOTAL_S=3600 PORCENTAJE_WEB=60
#   → 2160s web + 1440s gamer, divididos en turnos de TURNO_S segundos
#   → resultado: web(900s) gamer(600s) web(900s) gamer(600s) ...
#
TIEMPO_TOTAL_S  = int(os.environ.get("TIEMPO_TOTAL_S",  "3600"))  # duración total sesión
PORCENTAJE_WEB  = int(os.environ.get("PORCENTAJE_WEB",  "50"))    # % de tiempo para web (0-100)
TURNO_S         = int(os.environ.get("TURNO_S",         "900"))   # duración de cada turno individual

# ── Rutas a los scripts de los agentes ───────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
SCRIPT_WEB  = os.path.join(BASE_DIR, "agentev7.py")
SCRIPT_GAMER = os.path.join(BASE_DIR, "agentegamer3.py")

# ══════════════════════════════════════════════════════════
#  UTILIDADES
# ══════════════════════════════════════════════════════════

proceso_activo: "subprocess.Popen | None" = None


def _handler_sigint(sig, frame):
    """Ctrl+C: termina el subproceso activo y sale limpiamente."""
    global proceso_activo
    print("\n[Orquestador] Ctrl+C detectado. Terminando agente activo...")
    if proceso_activo and proceso_activo.poll() is None:
        proceso_activo.terminate()
        try:
            proceso_activo.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proceso_activo.kill()
    sys.exit(0)


signal.signal(signal.SIGINT, _handler_sigint)


def _segundos_a_hms(s: int) -> str:
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {sec}s"
    if m:
        return f"{m}m {sec}s"
    return f"{sec}s"


def _banner(turno: int, total: int, agente: str, duracion: int, inicio: datetime):
    fin = inicio + timedelta(seconds=duracion)
    print()
    print("=" * 60)
    print(f"  Turno {turno}/{total}  |  Agente: {agente.upper()}")
    print(f"  Duración: {_segundos_a_hms(duracion)}")
    print(f"  Inicio:   {inicio.strftime('%H:%M:%S')}  →  Fin: {fin.strftime('%H:%M:%S')}")
    print("=" * 60)


def _pausa(segundos: int):
    if segundos <= 0:
        return
    print(f"\n[Orquestador] Pausa de {segundos}s antes del siguiente agente...")
    for restante in range(segundos, 0, -5):
        print(f"  {restante}s restantes...", end="\r")
        time.sleep(min(5, restante))
    print()


def lanzar_agente(agente: str, duracion: int) -> int:
    """
    Lanza el agente indicado como subproceso con la duración configurada.
    Bloquea hasta que el agente termina.
    Devuelve el código de retorno del proceso.
    """
    global proceso_activo

    if agente == "web":
        script = SCRIPT_WEB
        env_dur = "DURACION_WEB_S"
    elif agente == "gamer":
        script = SCRIPT_GAMER
        env_dur = "DURACION_GAMER_S"
    else:
        print(f"[Orquestador] ❌ Agente desconocido: '{agente}'. Usa 'web' o 'gamer'.")
        return -1

    if not os.path.isfile(script):
        print(f"[Orquestador] ❌ Script no encontrado: {script}")
        return -1

    # Heredar el entorno actual y sobreescribir la duración
    env = os.environ.copy()
    env[env_dur] = str(duracion)

    print(f"[Orquestador] Lanzando: python {os.path.basename(script)} ({env_dur}={duracion})")

    proceso_activo = subprocess.Popen(
        [sys.executable, script],
        env=env,
    )

    ret = proceso_activo.wait()
    proceso_activo = None

    estado = "✅ completado" if ret == 0 else f"⚠️  código de salida {ret}"
    print(f"[Orquestador] Agente {agente} {estado}.")
    return ret


def _construir_turnos_tiempo_total() -> list:
    """
    Reparte TIEMPO_TOTAL_S entre web y gamer según PORCENTAJE_WEB,
    alternando turnos de TURNO_S segundos.

    Ejemplo: TIEMPO_TOTAL_S=3600, PORCENTAJE_WEB=60, TURNO_S=900
      → tiempo_web=2160s, tiempo_gamer=1440s
      → turnos: web(900) gamer(600) web(900) gamer(600) web(360)
    """
    porcentaje_web   = max(0, min(100, PORCENTAJE_WEB))
    porcentaje_gamer = 100 - porcentaje_web

    tiempo_web   = int(TIEMPO_TOTAL_S * porcentaje_web   / 100)
    tiempo_gamer = int(TIEMPO_TOTAL_S * porcentaje_gamer / 100)

    print(f"[Orquestador] tiempo_total: {_segundos_a_hms(TIEMPO_TOTAL_S)} | "
          f"web {porcentaje_web}% ({_segundos_a_hms(tiempo_web)}) | "
          f"gamer {porcentaje_gamer}% ({_segundos_a_hms(tiempo_gamer)}) | "
          f"turno: {_segundos_a_hms(TURNO_S)}")

    restante_web   = tiempo_web
    restante_gamer = tiempo_gamer
    turnos = []

    # Alterna web → gamer mientras quede tiempo en alguno
    for agente in ["web", "gamer"] * (TIEMPO_TOTAL_S // TURNO_S + 2):
        if restante_web <= 0 and restante_gamer <= 0:
            break
        if agente == "web":
            if restante_web <= 0:
                continue
            dur = min(TURNO_S, restante_web)
            restante_web -= dur
        else:
            if restante_gamer <= 0:
                continue
            dur = min(TURNO_S, restante_gamer)
            restante_gamer -= dur
        if dur > 0:
            turnos.append({"agente": agente, "duracion": dur})

    return turnos


def construir_turnos() -> list:
    """Construye la lista de turnos según el modo configurado."""
    if MODO == "secuencia":
        return list(SECUENCIA)

    if MODO == "tiempo_total":
        return _construir_turnos_tiempo_total()

    # Modo cíclico: repite ORDEN × CICLOS
    turnos = []
    duraciones = {"web": DURACION_WEB_S, "gamer": DURACION_GAMER_S}
    for _ in range(CICLOS):
        for agente in ORDEN:
            agente = agente.strip()
            if agente not in duraciones:
                print(f"[Orquestador] ⚠️  Agente desconocido en ORDEN: '{agente}'. Ignorado.")
                continue
            turnos.append({"agente": agente, "duracion": duraciones[agente]})
    return turnos


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    turnos = construir_turnos()

    if not turnos:
        print("[Orquestador] ❌ No hay turnos definidos. Revisa MODO, ORDEN y CICLOS.")
        sys.exit(1)

    total_s = sum(t["duracion"] for t in turnos) + PAUSA_ENTRE_S * (len(turnos) - 1)

    print("=" * 60)
    print("  Orquestador de Agentes TFM")
    print("=" * 60)
    print(f"  Modo:           {MODO}")
    if MODO == "ciclico":
        print(f"  Ciclos:         {CICLOS}")
        print(f"  Orden:          {' → '.join(ORDEN)}")
        print(f"  Duración web:   {_segundos_a_hms(DURACION_WEB_S)} por turno")
        print(f"  Duración gamer: {_segundos_a_hms(DURACION_GAMER_S)} por turno")
    elif MODO == "tiempo_total":
        print(f"  Tiempo total:   {_segundos_a_hms(TIEMPO_TOTAL_S)}")
        print(f"  Web:            {PORCENTAJE_WEB}%  ({_segundos_a_hms(int(TIEMPO_TOTAL_S * PORCENTAJE_WEB / 100))})")
        print(f"  Gamer:          {100 - PORCENTAJE_WEB}%  ({_segundos_a_hms(int(TIEMPO_TOTAL_S * (100 - PORCENTAJE_WEB) / 100))})")
        print(f"  Tamaño turno:   {_segundos_a_hms(TURNO_S)}")
    print(f"  Turnos totales: {len(turnos)}")
    print(f"  Pausa entre:    {PAUSA_ENTRE_S}s")
    print(f"  Tiempo total:   ~{_segundos_a_hms(total_s)}")
    print(f"  Fin estimado:   {(datetime.now() + timedelta(seconds=total_s)).strftime('%H:%M:%S')}")
    print("=" * 60)
    print()

    for i, turno in enumerate(turnos, start=1):
        agente   = turno["agente"]
        duracion = turno["duracion"]
        inicio   = datetime.now()

        _banner(i, len(turnos), agente, duracion, inicio)
        lanzar_agente(agente, duracion)

        if i < len(turnos):
            _pausa(PAUSA_ENTRE_S)

    print()
    print("=" * 60)
    print("  Sesión orquestada completada.")
    print("=" * 60)
