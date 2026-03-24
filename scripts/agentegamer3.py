#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agentegamer3.py — Agente Gamer v3

Mejoras sobre agentegamer2.py:
  1. Discord sin coordenadas fijas:
       - Detecta si Discord ya está en ejecución (tasklist).
       - Navega al canal de voz mediante URI deep link (discord://...).
       - pywinauto busca el botón "Unirse"/"Join" por texto en la UI, no por posición.
       - Fallback: si pywinauto no encuentra el botón, asume que ya está en el canal.
  2. Duración configurable: constante DURACION_TOTAL_SEGUNDOS o env var DURACION_GAMER_S.
  3. Secuencia de juego en bucle hasta agotar el tiempo, con variación temporal
     y pausa aleatoria entre repeticiones.
  4. Scroll soportado en la secuencia. ESC de la grabación ignorado.
  5. Shutdown limpio (KeyboardInterrupt + threading.Event).
  6. Steam lanzado via protocolo steam://rungameid/ (más fiable que .lnk con args).

Uso:
  python agentegamer3.py                        # 1 hora por defecto
  DURACION_GAMER_S=1800 python agentegamer3.py  # 30 minutos
  DURACION_GAMER_S=300  python agentegamer3.py  # 5 minutos (prueba rápida)

Requisitos nuevos (instalar si no están):
  pip install pywinauto pyttsx3 soundfile
"""

import os
import subprocess
import time
import random
import json
import threading

import pyautogui

pyautogui.PAUSE = 0.03  # mínima pausa de seguridad

# ══════════════════════════════════════════════════════════
#  CONFIGURACIÓN
# ══════════════════════════════════════════════════════════

# ── Duración ─────────────────────────────────────────────
DURACION_TOTAL_SEGUNDOS = int(os.environ.get("DURACION_GAMER_S", "300"))

# ── Discord ───────────────────────────────────────────────
# Activa Modo Desarrollador en Discord (Ajustes → Avanzado → Modo desarrollador)
# Luego: clic derecho sobre el servidor → "Copiar ID"
#         clic derecho sobre el canal de voz → "Copiar ID"
GUILD_ID         = os.environ.get("DISCORD_GUILD_ID",   "1402341988799479910")  # ID del servidor
VOICE_CHANNEL_ID = os.environ.get("DISCORD_CHANNEL_ID", "1402341988799479915")  # ID del canal de voz

DISCORD_EXE_NAME      = "Discord.exe"
DISCORD_PATH          = (
    r"C:\Users\juanc\AppData\Roaming\Microsoft\Windows"
    r"\Start Menu\Programs\Discord Inc\Discord.lnk"
)
DISCORD_LAUNCH_WAIT   = 14   # segundos de espera tras lanzar Discord
DISCORD_DEEPLINK_WAIT = 5    # segundos tras abrir la URI para que Discord reaccione
DISCORD_JOIN_TIMEOUT  = 15   # segundos buscando el botón "Unirse" con pywinauto

# ── Steam / juego ─────────────────────────────────────────
STEAM_GAME_ID             = int(os.environ.get("STEAM_GAME_ID",    "489560"))
TIEMPO_ESPERA_CARGA_JUEGO = int(os.environ.get("GAME_LOAD_WAIT",   "30"))

# ── Secuencia grabada ─────────────────────────────────────
RUTA_SECUENCIA     = os.environ.get("SEQUENCE_FILE", "secuencia_astroflux_avanzado.json")
PAUSA_ENTRE_LOOPS  = (5.0, 15.0)    # pausa aleatoria entre repeticiones (seg)
VARIACION_TEMPORAL = (0.85, 1.15)   # factor escala de tiempo por loop (variedad)

# ── Voz Discord ───────────────────────────────────────────
TALK_KEY          = os.environ.get("TALK_KEY",      "")           # PTT; vacío = voice activity
VOICE_DEVICE_HINT = os.environ.get("VOICE_DEVICE",  "CABLE Input") # VB-CABLE

# Patrón de turnos de conversación
TURNO_SILENCIO_MIN   = float(os.environ.get("TURNO_SILENCIO_MIN", "15"))  # silencio entre turnos (s)
TURNO_SILENCIO_MAX   = float(os.environ.get("TURNO_SILENCIO_MAX", "45"))
TURNO_FRASES_MIN     = int(os.environ.get("TURNO_FRASES_MIN", "2"))       # frases por turno
TURNO_FRASES_MAX     = int(os.environ.get("TURNO_FRASES_MAX", "4"))
TURNO_PAUSA_MIN      = float(os.environ.get("TURNO_PAUSA_MIN", "0.5"))    # pausa entre frases (s)
TURNO_PAUSA_MAX      = float(os.environ.get("TURNO_PAUSA_MAX", "2.5"))
VOICE_MIN_LEN        = float(os.environ.get("VOICE_MIN_LEN", "1.0"))      # duración mín babble fallback
VOICE_MAX_LEN        = float(os.environ.get("VOICE_MAX_LEN", "4.5"))      # duración máx babble fallback

# Frases de gaming en español que emitirá pyttsx3
FRASES_GAMER = [
    "voy por ti", "cuidado por la izquierda", "me han eliminado",
    "voy a reaparecer", "necesito ayuda", "cubridme",
    "ya lo tengo", "base bajo ataque", "recargando",
    "vamos vamos vamos", "nos están flanqueando", "a por ellos",
    "me retiro un momento", "eso es mío", "qué daño más bestia",
    "buen trabajo", "cuidado detrás", "estoy casi muerto",
    "uso el ultimate", "esperadme aquí", "equipo increíble",
    "qué partida más buena", "otro más", "venga va",
    "dónde están", "por aquí", "os sigo",
]

# ── Librerías opcionales ──────────────────────────────────
try:
    import numpy as np
    import sounddevice as sd
except ImportError:
    np = sd = None

try:
    import soundfile as sf
except ImportError:
    sf = None

try:
    import pyttsx3
    PYTTSX3_OK = True
except ImportError:
    pyttsx3 = None
    PYTTSX3_OK = False

try:
    from pywinauto import Desktop
    PYWINAUTO_OK = True
except ImportError:
    PYWINAUTO_OK = False


# ══════════════════════════════════════════════════════════
#  DISCORD: lanzar + unirse al canal sin coordenadas
# ══════════════════════════════════════════════════════════

def _discord_corriendo() -> bool:
    """True si Discord.exe está en la lista de procesos."""
    try:
        r = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {DISCORD_EXE_NAME}"],
            capture_output=True, text=True, timeout=5,
        )
        return DISCORD_EXE_NAME.lower() in r.stdout.lower()
    except Exception:
        return False


def lanzar_discord() -> None:
    """Lanza Discord si no está corriendo y espera a que cargue."""
    if _discord_corriendo():
        print("[Discord] Ya está en ejecución.")
        return
    print("[Discord] No detectado. Lanzando...")
    try:
        subprocess.Popen([DISCORD_PATH], shell=True)
        print(f"[Discord] Esperando {DISCORD_LAUNCH_WAIT}s para que cargue...")
        time.sleep(DISCORD_LAUNCH_WAIT)
        if _discord_corriendo():
            print("[Discord] ✅ Proceso detectado.")
        else:
            print("[Discord] ⚠️  No se detecta el proceso tras la espera.")
    except Exception as e:
        print(f"[Discord] ❌ Error al lanzar: {e}")


def _abrir_deeplink() -> bool:
    """
    Abre la URI discord://... para que Discord navegue directamente al canal de voz.
    Devuelve False si no hay IDs configurados.
    """
    if not GUILD_ID or not VOICE_CHANNEL_ID:
        print(
            "[Discord] ⚠️  GUILD_ID / VOICE_CHANNEL_ID vacíos. "
            "Rellena las constantes (o env vars DISCORD_GUILD_ID / DISCORD_CHANNEL_ID)."
        )
        return False

    uri = f"discord://discord.com/channels/{GUILD_ID}/{VOICE_CHANNEL_ID}"
    print(f"[Discord] Abriendo deep link → {uri}")
    try:
        subprocess.Popen(["start", uri], shell=True)
        time.sleep(DISCORD_DEEPLINK_WAIT)
        return True
    except Exception as e:
        print(f"[Discord] ❌ Error abriendo URI: {e}")
        return False


def _buscar_boton_unirse(timeout: float = DISCORD_JOIN_TIMEOUT) -> bool:
    """
    Usa pywinauto (UI Automation) para buscar en la ventana de Discord
    un botón cuyo texto contenga 'Unirse' o 'Join' y hace clic en él.
    Devuelve True si lo encontró y clicó.
    """
    if not PYWINAUTO_OK:
        print("[Discord] pywinauto no disponible. Saltando búsqueda de botón.")
        return False

    textos = {"unirse", "join", "unirse al canal", "join channel",
              "join voice", "conectar", "connect"}
    deadline = time.time() + timeout
    intentos = 0

    print(f"[Discord] Buscando botón 'Unirse' con pywinauto (timeout={timeout}s)...")

    while time.time() < deadline:
        intentos += 1
        try:
            # Busca todas las ventanas de Discord
            ventanas = Desktop(backend="uia").windows(title_re=".*Discord.*")
            for win in ventanas:
                # Ignora ventanas muy pequeñas (overlays, notificaciones)
                try:
                    rect = win.rectangle()
                    if (rect.width() < 300) or (rect.height() < 200):
                        continue
                except Exception:
                    pass

                # Recorre todos los controles buscando texto coincidente
                for tipo_ctrl in ("Button", "Hyperlink", "Text", "Custom", "ListItem"):
                    try:
                        for el in win.descendants(control_type=tipo_ctrl):
                            try:
                                nombre = (el.window_text() or "").strip().lower()
                                if nombre and any(t in nombre for t in textos):
                                    print(f"[Discord] ✅ Botón encontrado: '{el.window_text().strip()}'")
                                    el.click_input()
                                    time.sleep(1.5)
                                    return True
                            except Exception:
                                continue
                    except Exception:
                        continue

        except Exception as e:
            if intentos == 1:
                print(f"[Discord] pywinauto: {e}")

        time.sleep(0.8)

    print(
        "[Discord] ⚠️  Botón 'Unirse' no encontrado "
        "(quizá ya estás en el canal o no se mostró el diálogo)."
    )
    return False


def unirse_canal_discord() -> None:
    """
    Flujo completo para unirse al canal de voz:
    1. Abre URI deep link → Discord navega al canal.
    2. pywinauto busca el botón 'Unirse' por texto y lo clica.
    3. Si no aparece el botón, asume que ya está conectado.
    """
    link_abierto = _abrir_deeplink()
    if link_abierto:
        _buscar_boton_unirse()
    else:
        print("[Discord] Sin deep link; asumiendo que ya estás en el canal de voz.")
    time.sleep(1)
    print("[Discord] Paso de unión completado.")


# ══════════════════════════════════════════════════════════
#  STEAM: lanzar juego
# ══════════════════════════════════════════════════════════

def lanzar_juego_steam(app_id: int) -> None:
    """Lanza un juego de Steam usando el protocolo steam://rungameid/."""
    try:
        print(f"[Steam] Lanzando juego ID={app_id} via steam://rungameid/...")
        os.startfile(f"steam://rungameid/{app_id}")
        print(f"[Steam] Esperando {TIEMPO_ESPERA_CARGA_JUEGO}s a que cargue...")
        time.sleep(TIEMPO_ESPERA_CARGA_JUEGO)
        print("[Steam] ✅ Juego listo.")
    except Exception as e:
        print(f"[Steam] ❌ Error: {e}")


# ══════════════════════════════════════════════════════════
#  SECUENCIA DE JUEGO: bucle hasta agotar el tiempo
# ══════════════════════════════════════════════════════════

def cargar_secuencia(path: str) -> list:
    if not os.path.isfile(path):
        print(f"[Secuencia] ⚠️  '{path}' no existe. Se usará idle de teclado.")
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            eventos = json.load(f)
        duracion = eventos[-1][1] if eventos else 0
        print(f"[Secuencia] Cargados {len(eventos)} eventos (~{duracion:.1f}s) desde {path}")
        return eventos
    except Exception as e:
        print(f"[Secuencia] ❌ Error al cargar: {e}")
        return []


def _limpiar_tecla(s: str) -> str:
    return s.replace("Key.", "").replace("'", "").lower()


def _convertir_boton(s: str) -> str:
    s = s.lower()
    if "right"  in s: return "right"
    if "middle" in s: return "middle"
    return "left"


def _reproducir_una_vez(eventos: list, scale: float, fin_tiempo: float) -> None:
    """
    Reproduce la secuencia una vez aplicando factor 'scale' al tiempo.
    Comprueba fin_tiempo antes de cada evento para salir limpiamente.
    ESC se ignora (era el comando para parar el grabador).
    """
    inicio = time.time()
    teclas_activas: set = set()
    botones_activos: set = set()

    try:
        for ev in eventos:
            if time.time() >= fin_tiempo:
                break

            tipo = ev[0]
            t_objetivo = ev[1] * scale
            espera = t_objetivo - (time.time() - inicio)

            # Espera en pequeños trozos para poder salir a tiempo
            if espera > 0:
                fin_espera = time.time() + espera
                while time.time() < fin_espera and time.time() < fin_tiempo:
                    time.sleep(min(0.04, fin_espera - time.time()))

            if time.time() >= fin_tiempo:
                break

            try:
                if tipo == "key_down":
                    tecla = _limpiar_tecla(ev[2])
                    if tecla == "esc":
                        continue
                    pyautogui.keyDown(tecla)
                    teclas_activas.add(tecla)

                elif tipo == "key_up":
                    tecla = _limpiar_tecla(ev[2])
                    if tecla == "esc":
                        continue
                    pyautogui.keyUp(tecla)
                    teclas_activas.discard(tecla)

                elif tipo == "mouse_down":
                    _, _, x, y, b = ev
                    boton = _convertir_boton(b)
                    pyautogui.mouseDown(x=x, y=y, button=boton)
                    botones_activos.add(boton)

                elif tipo == "mouse_up":
                    _, _, x, y, b = ev
                    boton = _convertir_boton(b)
                    pyautogui.mouseUp(x=x, y=y, button=boton)
                    botones_activos.discard(boton)

                elif tipo == "scroll":
                    x, y, dy = ev[2], ev[3], ev[5]
                    pyautogui.scroll(int(dy), x=x, y=y)

            except Exception:
                pass  # no romper el loop por un evento individual

    finally:
        # Siempre liberar teclas/botones al terminar o interrumpir
        for t in list(teclas_activas):
            try: pyautogui.keyUp(t)
            except Exception: pass
        for b in list(botones_activos):
            try: pyautogui.mouseUp(button=b)
            except Exception: pass


def _idle_aleatorio(fin_tiempo: float, stop_event: threading.Event) -> None:
    """
    Fallback sin secuencia: mueve el personaje con WASD aleatoriamente
    durante un rato corto.
    """
    for _ in range(random.randint(3, 8)):
        if stop_event.is_set() or time.time() >= fin_tiempo:
            break
        tecla = random.choice(["w", "a", "s", "d"])
        dur = random.uniform(0.3, 1.5)
        pyautogui.keyDown(tecla)
        stop_event.wait(timeout=dur)
        pyautogui.keyUp(tecla)
        stop_event.wait(timeout=random.uniform(0.1, 0.5))


def bucle_juego(eventos: list, stop_event: threading.Event, fin_tiempo: float) -> None:
    """
    Repite la secuencia en bucle con variación temporal hasta que:
    - Se alcance fin_tiempo (duración configurada), o
    - Se active stop_event (Ctrl+C).
    """
    n = 0
    while not stop_event.is_set() and time.time() < fin_tiempo:
        n += 1
        restante = fin_tiempo - time.time()
        scale = random.uniform(*VARIACION_TEMPORAL)
        print(f"[Juego] Iteración {n} | escala={scale:.2f} | restante={restante:.0f}s")

        if eventos:
            _reproducir_una_vez(eventos, scale, fin_tiempo)
        else:
            _idle_aleatorio(fin_tiempo, stop_event)

        # Pausa entre iteraciones (usa stop_event.wait para responder a Ctrl+C)
        if not stop_event.is_set() and time.time() < fin_tiempo:
            pausa = random.uniform(*PAUSA_ENTRE_LOOPS)
            pausa = min(pausa, fin_tiempo - time.time())
            if pausa > 0:
                print(f"[Juego] Pausa {pausa:.1f}s entre iteraciones...")
                stop_event.wait(timeout=pausa)

    print(f"[Juego] Sesión finalizada tras {n} iteración(es).")


# ══════════════════════════════════════════════════════════
#  VOZ SINTÉTICA DISCORD
# ══════════════════════════════════════════════════════════

def _find_output_device() -> "int | None":
    if not sd:
        return None
    for idx, d in enumerate(sd.query_devices()):
        if d.get("max_output_channels", 0) > 0 and VOICE_DEVICE_HINT.lower() in d.get("name", "").lower():
            return idx
    return None


# ── Síntesis formántica (fallback sin pyttsx3) ────────────────────────────────
def _sintetizar_formantes(seconds: float, samplerate: int = 16000):
    """
    Genera audio con frecuencias formánticas típicas del habla humana (F1, F2, F3)
    mezcladas con ruido, produciendo un sonido más parecido a voz que ruido blanco.
    Discord VAD lo detecta con más fiabilidad que el babble anterior.
    """
    if not np:
        return None
    n = int(seconds * samplerate)
    t = np.linspace(0, seconds, n, dtype=np.float32)

    # F0 (tono fundamental): 85–180 Hz según "hablante"
    f0 = random.uniform(85, 180)
    # Formantes principales del habla: F1, F2, F3
    f1 = random.uniform(400,  900)
    f2 = random.uniform(900, 2400)
    f3 = random.uniform(2400, 3500)

    # Excitación: tren de pulsos simulado con armónicos del F0
    excitacion = sum(
        (1.0 / (k ** 0.8)) * np.sin(2 * np.pi * f0 * k * t + random.uniform(0, np.pi))
        for k in range(1, 7)
    ).astype(np.float32)

    # Filtrado: resaltar formantes sumando señales seno amortiguadas
    bw = 80  # ancho de banda de cada formante
    def resonancia(f, bw):
        decay = np.exp(-np.pi * bw * t)
        return (decay * np.sin(2 * np.pi * f * t)).astype(np.float32)

    voz = excitacion + 0.6 * resonancia(f1, bw) + 0.4 * resonancia(f2, bw) + 0.2 * resonancia(f3, bw)

    # Ruido unvoiced (consonantes)
    ruido = np.random.randn(n).astype(np.float32) * 0.15

    # Envolvente de amplitud: simula sílabas (varios pulsos de energía)
    n_silabas = max(1, int(seconds * random.uniform(2.5, 4.5)))
    env = np.zeros(n, dtype=np.float32)
    for _ in range(n_silabas):
        centro = random.uniform(0.1, 0.9) * n
        ancho  = random.uniform(0.04, 0.12) * n
        x = np.arange(n, dtype=np.float32)
        env += np.exp(-0.5 * ((x - centro) / ancho) ** 2)
    env = np.clip(env, 0, 1)

    audio = (voz + ruido) * env * random.uniform(0.20, 0.40)
    # Normalizar para evitar clipping
    pico = np.max(np.abs(audio))
    if pico > 0:
        audio = audio / pico * 0.85
    return audio.astype(np.float32)


# ── TTS real con pyttsx3 → array numpy ───────────────────────────────────────
def _tts_a_array(frase: str, samplerate: int = 16000):
    """
    Usa pyttsx3 para sintetizar la frase en un archivo WAV temporal,
    lo lee con soundfile y devuelve (array_float32, samplerate).
    Requiere pyttsx3 + soundfile + numpy.
    Devuelve None si algo falla.
    """
    if not (PYTTSX3_OK and sf and np):
        return None

    import tempfile
    tmp = None
    try:
        engine = pyttsx3.init()
        engine.setProperty("rate",   random.randint(140, 185))   # velocidad natural
        engine.setProperty("volume", random.uniform(0.75, 1.0))

        # Intentar voz en español si el sistema la tiene
        voces = engine.getProperty("voices")
        voz_es = next((v for v in voces if "es" in (v.languages[0] if v.languages else "").lower()
                       or "spanish" in v.name.lower()), None)
        if voz_es:
            engine.setProperty("voice", voz_es.id)

        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            tmp = f.name

        engine.save_to_file(frase, tmp)
        engine.runAndWait()
        engine.stop()

        data, sr = sf.read(tmp, dtype="float32", always_2d=False)
        if data.ndim > 1:
            data = data[:, 0]   # mono

        # Remuestrear a samplerate si es necesario (interpolación simple)
        if sr != samplerate:
            n_nuevo = int(len(data) * samplerate / sr)
            data = np.interp(
                np.linspace(0, len(data) - 1, n_nuevo),
                np.arange(len(data)),
                data
            ).astype(np.float32)

        return data, samplerate

    except Exception as e:
        print(f"[Voz] pyttsx3 error: {e}")
        return None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except Exception:
                pass


# ── Emitir un fragmento de audio por VB-CABLE ────────────────────────────────
def _emitir_audio(audio, samplerate: int, dev: int) -> None:
    """Pulsa PTT (si está configurado), reproduce audio y suelta PTT."""
    if TALK_KEY:
        pyautogui.keyDown(TALK_KEY)
    try:
        sd.play(audio, samplerate=samplerate, device=dev, blocking=True)
    finally:
        if TALK_KEY:
            pyautogui.keyUp(TALK_KEY)
    time.sleep(0.15)


# ── Emitter principal con patrón de turnos ────────────────────────────────────
def discord_voice_emitter(stop_event: threading.Event) -> None:
    """
    Simula conversación de gamer con patrón de turnos realista:
      - Silencio largo entre turnos (TURNO_SILENCIO_MIN – TURNO_SILENCIO_MAX s)
      - Ráfaga de TURNO_FRASES_MIN–MAX frases por turno
      - Pausa corta entre frases del mismo turno (TURNO_PAUSA_MIN–MAX s)

    Cadena de prioridad para generar el audio:
      1. pyttsx3 → WAV temporal → array  (voz real, pasa VAD de Discord)
      2. síntesis formántica               (fallback mejorado, numpy)
      3. nada                              (sin librerías de audio)
    """
    if not sd:
        print("[Voz] sounddevice no instalado. Sin emisión de voz.")
        return

    dev = _find_output_device()
    if dev is None:
        print(f"[Voz] Dispositivo '{VOICE_DEVICE_HINT}' no encontrado. Sin voz.")
        return

    modo = "pyttsx3 (TTS real)" if PYTTSX3_OK and sf and np else \
           "síntesis formántica" if np else "—"
    print(f"[Voz] ✅ Dispositivo idx={dev} | Modo: {modo}")

    turno = 0
    while not stop_event.is_set():

        # ── Silencio entre turnos ──────────────────────────────────────────
        silencio = random.uniform(TURNO_SILENCIO_MIN, TURNO_SILENCIO_MAX)
        stop_event.wait(timeout=silencio)
        if stop_event.is_set():
            break

        # ── Ráfaga de frases (un turno de habla) ──────────────────────────
        turno += 1
        n_frases = random.randint(TURNO_FRASES_MIN, TURNO_FRASES_MAX)
        print(f"[Voz] Turno {turno}: {n_frases} frase(s)")

        for i in range(n_frases):
            if stop_event.is_set():
                break

            # Generar audio: intentar TTS real primero
            audio_data = None
            sr = 16000

            if PYTTSX3_OK and sf and np:
                frase = random.choice(FRASES_GAMER)
                resultado = _tts_a_array(frase, samplerate=sr)
                if resultado is not None:
                    audio_data, sr = resultado
                    print(f"[Voz]   [{i+1}/{n_frases}] TTS: \"{frase}\"")

            # Fallback: síntesis formántica
            if audio_data is None and np:
                dur = random.uniform(VOICE_MIN_LEN, VOICE_MAX_LEN)
                audio_data = _sintetizar_formantes(dur, samplerate=sr)
                if audio_data is not None:
                    print(f"[Voz]   [{i+1}/{n_frases}] Formantes ({dur:.1f}s)")

            if audio_data is None:
                continue

            try:
                _emitir_audio(audio_data, sr, dev)
            except Exception as e:
                print(f"[Voz] Error reproduciendo: {e}")

            # Pausa corta entre frases del mismo turno
            if i < n_frases - 1 and not stop_event.is_set():
                stop_event.wait(timeout=random.uniform(TURNO_PAUSA_MIN, TURNO_PAUSA_MAX))


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    h = DURACION_TOTAL_SEGUNDOS // 3600
    m = (DURACION_TOTAL_SEGUNDOS % 3600) // 60

    print("=" * 55)
    print("  Agente Gamer v3")
    print("=" * 55)
    print(f"  Duración:     {DURACION_TOTAL_SEGUNDOS}s ({h}h {m}m)")
    print(f"  Steam ID:     {STEAM_GAME_ID}")
    print(f"  Secuencia:    {RUTA_SECUENCIA}")
    print(f"  Discord:      guild={GUILD_ID or '⚠️  sin configurar'}  "
          f"canal={VOICE_CHANNEL_ID or '⚠️  sin configurar'}")
    print(f"  pywinauto:    {'✅ disponible' if PYWINAUTO_OK else '❌ no instalado'}")
    print(f"  audio libs:   {'✅ disponible' if sd else '❌ no instaladas (sin voz)'}")
    voz_modo = "pyttsx3 TTS real" if (PYTTSX3_OK and sf and np) else \
               "síntesis formántica" if np else "❌ sin voz"
    print(f"  modo voz:     {voz_modo}")
    print("=" * 55)
    print()

    fin_tiempo = time.time() + DURACION_TOTAL_SEGUNDOS

    # 1) Lanzar Discord y unirse al canal de voz
    lanzar_discord()
    unirse_canal_discord()

    # 2) Lanzar el juego
    lanzar_juego_steam(STEAM_GAME_ID)

    # 3) Cargar secuencia grabada
    eventos = cargar_secuencia(RUTA_SECUENCIA)

    # 4) Hilo de voz sintética
    stop_event = threading.Event()
    voice_thread = threading.Thread(
        target=discord_voice_emitter, args=(stop_event,), daemon=True
    )
    voice_thread.start()

    # 5) Bucle principal del juego
    try:
        bucle_juego(eventos, stop_event, fin_tiempo)
    except KeyboardInterrupt:
        print("\n[Main] Ctrl+C detectado. Cerrando limpiamente...")
    finally:
        stop_event.set()
        voice_thread.join(timeout=5)
        print()
        print("=" * 55)
        print("  Simulación completada.")
        print("=" * 55)
