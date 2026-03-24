import os
import re
import time
import json
import random
import requests
import undetected_chromedriver as uc
from datetime import datetime, timedelta
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import subprocess, re
import shutil
from pathlib import Path

# ========== CONFIGURACIÓN ==========
# Las credenciales se leen de variables de entorno o de un archivo .env
# Copia .env.example como .env y rellena tus valores reales

# --- Claves/servicios ---
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# --- Rutas Chrome/Driver ---
CHROME_PATH = os.environ.get(
    "CHROME_PATH",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe"
)

# --- Perfil persistente (para guardar sesión/cookies) ---
PROFILE_DIR = os.environ.get(
    "CHROME_PROFILE_DIR",
    os.path.join(os.path.dirname(__file__), "chrome_profile_tfm")
)
os.makedirs(PROFILE_DIR, exist_ok=True)

# --- Credenciales (Gmail y Twitter) ---
GMAIL_USER      = os.environ.get("GMAIL_USER", "")
GMAIL_PASSWORD  = os.environ.get("GMAIL_PASSWORD", "")
TWITTER_USERNAME = os.environ.get("TWITTER_USERNAME", "")

# --- Duración del agente ---
DURACION_TOTAL_SEGUNDOS = int(os.environ.get("DURACION_WEB_S", "3600"))

# --- Tipos permitidos para el LLM ---
ALLOWED_TIPOS = {
    "buscar_google", "abrir_url", "mirar_youtube", "revisar_correo", "ver_streaming", "usar_twitter"
}

# ========== Utilidades Chrome/uc ==========
def get_chrome_exe():
    """
    Devuelve la ruta al ejecutable de Chrome/Chromium.
    - Si usas Chrome portátil, DEVUELVE aquí su ruta (descomenta el return).
    """
    # 1) Si usas Chrome PORTÁTIL, descomenta y ajusta:
    # return r"C:\ruta\al\ChromePortable\Chrome.exe"

    # 2) Si CHROME_PATH existe, úsalo
    if CHROME_PATH and os.path.exists(CHROME_PATH):
        return CHROME_PATH

    # 3) Intenta obtener la ruta desde el registro de Windows (instalación estándar)
    try:
        import winreg
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for subkey in (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
            ):
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        path, _ = winreg.QueryValueEx(k, "Path")
                        exe = os.path.join(path, "chrome.exe")
                        if os.path.exists(exe):
                            return exe
                except OSError:
                    continue
    except Exception:
        pass

    # 4) Fallback: confía en que esté en PATH
    return "chrome.exe"

def get_chrome_major(exe_path):
    """Devuelve la versión mayor (int) de Chrome. Primero intenta el registro de Windows."""
    # 1) Registro de Windows (más fiable que subprocess en Windows)
    try:
        import winreg
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for subkey in (
                r"SOFTWARE\Google\Chrome\BLBeacon",
                r"SOFTWARE\WOW6432Node\Google\Chrome\BLBeacon",
            ):
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        version, _ = winreg.QueryValueEx(k, "version")
                        m = re.search(r"^(\d+)\.", str(version))
                        if m:
                            return int(m.group(1))
                except OSError:
                    continue
    except Exception:
        pass

    # 2) Fallback: ejecutar chrome --version
    try:
        out = subprocess.check_output([exe_path, "--version"], stderr=subprocess.STDOUT, text=True)
        m = re.search(r"\b(\d+)\.\d+\.\d+\.\d+\b", out)
        if m:
            return int(m.group(1))
    except Exception as e:
        print("No se pudo leer la versión de Chrome:", e)

    return None

def clear_uc_cache():
    """Borra la caché de undetected_chromedriver para forzar descarga del driver correcto."""
    candidates = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "undetected_chromedriver"),
        os.path.join(os.environ.get("TEMP", ""), "undetected_chromedriver"),
        os.path.join(os.environ.get("APPDATA", ""), "undetected_chromedriver"),
    ]
    for d in candidates:
        if d and os.path.isdir(d):
            try:
                shutil.rmtree(d, ignore_errors=True)
                print(f"🧹 Caché uc eliminada: {d}")
            except Exception as e:
                print(f"⚠️ No se pudo borrar {d}: {e}")

# ========== COOKIES: detectores robustos ==========
FRASES_COOKIES = [
    # Aceptar genérico
    "aceptar", "acepto", "sí, acepto", "si, acepto",
    "estoy de acuerdo", "de acuerdo", "entendido", "vale", "ok", "ok, acepto",
    # Aceptar todo / todas
    "aceptar todo", "aceptar todas", "aceptar todas las cookies",
    "aceptar el uso de cookies", "acepto el uso de cookies", "acepto las cookies",
    "usar cookies", "permitir el uso de cookies",
    # Aceptar + continuar/cerrar/seguir
    "aceptar y continuar", "aceptar y continuar navegando", "aceptar y seguir",
    "aceptar y seguir navegando", "aceptar y cerrar", "aceptar y cerrar mensaje",
    "aceptar y cerrar ventana", "cerrar y aceptar",
    # Aceptar + acción
    "aceptar y proceder", "aceptar y acceder", "aceptar y avanzar",
    "aceptar y guardar", "aceptar selección", "aceptar selección y continuar",
    "aceptar cookies", "aceptar cookies y continuar",
    # Permitir / consentir
    "permitir", "permitir todo", "permitir todas", "permitir todas las cookies",
    "permitir cookies", "consentir", "consentir y continuar", "doy mi consentimiento",
    # Otras / EN típicas
    "aceptar aviso de cookies", "continuar", "continuar y aceptar",
    "allow all", "accept all", "allow cookies", "accept cookies", "got it", "i agree"
]
FRASES_EVITAR = [
    "rechazar", "rechazo", "denegar", "no aceptar", "decline", "reject",
    "configurar", "configuración", "ajust", "preferencias", "opciones",
    "solo necesarias", "solo esenciales", "solo requeridas", "solo estrictamente necesarias",
    "manage", "settings", "only necessary", "essential only"
]
SELECTORES_CMP = [
    # OneTrust
    "#onetrust-accept-btn-handler", ".onetrust-accept-btn-handler",
    # Quantcast Choice
    ".qc-cmp2-summary-buttons .qc-cmp2-accept-all",
    ".qc-cmp2-footer .qc-cmp2-accept-all",
    "button[onclick*='acceptAll']",
    # Didomi
    "#didomi-notice-agree-button", ".didomi-components-button--accept",
    # Cookiebot
    "#CybotCookiebotDialogBodyLevelButtonAccept", "#CybotCookiebotDialogBodyButtonAccept",
    ".CybotCookiebotDialogBodyButtonAccept",
    # TrustArc
    "#truste-consent-button", ".trustarc-agree", "a.truste_button_1",
    # CookieYes / GDPR Cookie Consent
    "#wt-cli-accept-all-btn", ".cky-btn-accept", "#cookie_action_close_header",
    # Iubenda
    ".iubenda-cs-accept-btn",
    # Klaro
    ".klaro .cm-btn-accept", ".klaro .cm-btn-success",
    # Complianz
    "#cmplz-accept", ".cmplz-accept"
]

def _texto_elemento(el) -> str:
    return ((el.text or "") + " " + (el.get_attribute("aria-label") or "") + " " + (el.get_attribute("value") or "")).strip().lower()

def _es_aceptar(txt: str) -> bool:
    return any(fr in txt for fr in FRASES_COOKIES) and not any(bad in txt for bad in FRASES_EVITAR)

def _safe_click(driver, el) -> bool:
    try:
        if el.is_displayed() and el.is_enabled():
            try:
                el.click()
                return True
            except Exception:
                driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
                driver.execute_script("arguments[0].click();", el)
                return True
    except Exception:
        pass
    return False

def _buscar_y_click_por_selectores(driver) -> bool:
    for sel in SELECTORES_CMP:
        try:
            for b in driver.find_elements(By.CSS_SELECTOR, sel):
                if _safe_click(driver, b):
                    return True
        except Exception:
            continue
    return False

def _buscar_y_click_por_texto(driver) -> bool:
    xq = "//button|//a|//div[@role='button']|//input[@type='button' or @type='submit']"
    try:
        for el in driver.find_elements(By.XPATH, xq):
            txt = _texto_elemento(el)
            if txt and _es_aceptar(txt):
                if _safe_click(driver, el):
                    return True
    except Exception:
        pass
    return False

def _intentar_en_iframes(driver, max_depth=2, depth=0) -> bool:
    if depth > max_depth:
        return False
    try:
        if _buscar_y_click_por_selectores(driver) or _buscar_y_click_por_texto(driver):
            return True
        for fr in driver.find_elements(By.TAG_NAME, "iframe"):
            try:
                driver.switch_to.frame(fr)
                if _buscar_y_click_por_selectores(driver) or _buscar_y_click_por_texto(driver):
                    driver.switch_to.default_content()
                    return True
                if _intentar_en_iframes(driver, max_depth, depth+1):
                    driver.switch_to.default_content()
                    return True
                driver.switch_to.default_content()
            except Exception:
                try: driver.switch_to.default_content()
                except Exception: pass
                continue
    except Exception:
        try: driver.switch_to.default_content()
        except Exception: pass
    return False

def aceptar_cookies(driver, intentos: int = 3, pausita: float = 0.35) -> bool:
    aceptado = False
    for _ in range(intentos):
        try:
            driver.execute_script("window.scrollBy(0, 1);")
        except Exception:
            pass
        time.sleep(pausita)
        if _buscar_y_click_por_selectores(driver) or _buscar_y_click_por_texto(driver):
            aceptado = True
            break
        if _intentar_en_iframes(driver):
            aceptado = True
            break

    if not aceptado:
        try:
            yt_buttons = driver.find_elements(
                By.XPATH,
                "//button[.//span[contains(translate(., 'ACEPTOIAGREE','aceptoiagree'),'acepto') or contains(translate(., 'ACEPTOIAGREE','aceptoiagree'),'i agree')]]"
            )
            for b in yt_buttons:
                if _safe_click(driver, b):
                    aceptado = True
                    break
        except Exception:
            pass
    try: driver.switch_to.default_content()
    except Exception: pass
    return aceptado

# ===== JSON parsing helpers (robustos) =====
def limpiar_surrogates(texto: str) -> str:
    return re.sub(r'[\ud800-\udfff]', '', texto)

def _clean_possible_json(text: str) -> str:
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.IGNORECASE)
    if "{" in text and "}" in text:
        start = text.find("{")
        end = text.rfind("}")
        candidate = text[start:end+1]
    else:
        candidate = text
    candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
    return candidate.strip()

def _try_parse_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        try:
            return json.loads(text.replace("'", '"'))
        except Exception:
            return None

def _validar_accion(accion: dict) -> dict | None:
    if not isinstance(accion, dict):
        return None
    tipo = accion.get("tipo")
    if not isinstance(tipo, str):
        return None
    tipo = tipo.strip().split()[0].lower()
    if tipo not in ALLOWED_TIPOS:
        return None
    delay = accion.get("delay")
    if not isinstance(delay, int):
        delay = random.randint(10, 12)
    accion["delay"] = max(8, min(25, delay))

    if tipo == "buscar_google":
        termino = str(accion.get("termino", "")).strip()
        if not termino:
            accion["termino"] = random.choice([
                "últimas noticias de IA", "tendencias ciberseguridad 2025", "python asyncio tutorial"
            ])
    elif tipo == "abrir_url":
        url = str(accion.get("url", "")).strip()
        if not url.startswith("http"):
            accion["url"] = "https://www.bbc.com/mundo"
    elif tipo == "mirar_youtube":
        busq = str(accion.get("busqueda", "")).strip()
        if not busq:
            accion["busqueda"] = random.choice(["noticias tecnología", "ciberseguridad", "tutorial python"])
    accion["tipo"] = tipo
    return accion

def generar_accion_fallback() -> dict:
    plantilla = [
        {"tipo": "buscar_google", "termino": random.choice([
            "últimas noticias tecnología", "ciberseguridad hoy", "mejores frameworks python 2025"
        ])},
        {"tipo": "mirar_youtube", "busqueda": random.choice([
            "programación en vivo", "noticias en vivo", "música en vivo"
        ])},
        {"tipo": "usar_twitter"},
        {"tipo": "abrir_url", "url": "https://www.bbc.com/mundo"},
    ]
    accion = random.choice(plantilla)
    accion["delay"] = random.randint(10, 20)
    return accion

# ========== LLM: decidir acción (robusto) ==========
def obtener_accion_json_llm(reintentos: int = 2):
    perfiles = [
        "un estudiante de informática curioso",
        "una persona interesada en tecnología",
        "alguien que quiere ver un vídeo educativo",
        "un lector habitual de periódicos online",
        "una persona aburrida que busca algo interesante"
    ]
    intenciones = [
        "quiere ver un vídeo en YouTube",
        "quiere leer noticias actuales",
        "quiere visitar una página web interesante",
        "quiere revisar su correo electrónico",
        "quiere ver un streaming en vivo",
        "quiere usar Twitter"
    ]
    perfil = random.choice(perfiles)
    intencion = random.choice(intenciones)

    prompt = (
        f"Eres un agente autónomo que simula el comportamiento de {perfil} que {intencion}.\n"
        "Elige UNA acción para realizar en el navegador.\n\n"
        "Opciones válidas:\n"
        "- buscar_google: requiere campo 'termino'\n"
        "- abrir_url: requiere campo 'url'\n"
        "- mirar_youtube: opcionalmente campo 'busqueda'\n"
        "- revisar_correo: no requiere campos adicionales\n"
        "- ver_streaming: (solo en YouTube Live)\n"
        "- usar_twitter: no requiere campos adicionales\n\n"
        "Incluye un campo \"delay\" (entero 8–25).\n"
        "Devuelve EXCLUSIVAMENTE un JSON válido, sin texto adicional ni comillas triples.\n"
        "Ejemplos:\n"
        "{ \"tipo\": \"buscar_google\", \"termino\": \"últimas noticias de IA\", \"delay\": 15 }\n"
        "{ \"tipo\": \"abrir_url\", \"url\": \"https://www.bbc.com/mundo\", \"delay\": 10 }\n"
        "{ \"tipo\": \"mirar_youtube\", \"busqueda\": \"videos de ciberseguridad\", \"delay\": 20 }\n"
        "{ \"tipo\": \"revisar_correo\", \"delay\": 20 }\n"
        "{ \"tipo\": \"ver_streaming\", \"delay\": 18 }\n"
        "{ \"tipo\": \"usar_twitter\", \"delay\": 16 }"
    )

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}

    for intento in range(1, reintentos + 1):
        data = {
            "model": "meta-llama/llama-4-scout-17b-16e-instruct",
            "temperature": 0.2 if intento == 1 else 0.3,
            "messages": [
                {"role": "system", "content": "Responde únicamente en JSON válido sin texto extra."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"}  # si no se soporta, lo ignoran
        }
        try:
            resp = requests.post(GROQ_API_URL, headers=headers, json=data, timeout=30)
            resp.raise_for_status()
            raw = resp.json()
            content = raw["choices"][0]["message"]["content"]
            print("📦 LLM:\n", content)

            cleaned = _clean_possible_json(content)
            accion = _try_parse_json(cleaned)
            accion = _validar_accion(accion)
            if accion:
                return accion
            else:
                print("⚠️ JSON recibido pero inválido. Reintentando…")
        except Exception as e:
            print(f"❌ Intento {intento}: error solicitando/parsing: {e}")

    print("⚠️ LLM sin JSON válido. Usando acción de respaldo.")
    return generar_accion_fallback()

# ========== YouTube helpers ==========
def youtube_click_random_organic_result(driver, only_live=False):
    try: aceptar_cookies(driver)
    except Exception: pass

    for _ in range(random.randint(1, 3)):
        driver.execute_script("window.scrollBy(0, document.body.scrollHeight * 0.25);")
        time.sleep(random.uniform(0.8, 1.5))

    candidatos = driver.find_elements(
        By.XPATH, "//ytd-video-renderer//a[@id='video-title' or @id='video-title-link']"
    )

    if only_live:
        vivos = []
        for a in candidatos:
            try:
                cont = a.find_element(By.XPATH, "./ancestor::ytd-video-renderer[1]")
                live_badge = cont.find_elements(
                    By.XPATH, ".//ytd-thumbnail-overlay-time-status-renderer[@overlay-style='LIVE']"
                )
                if live_badge:
                    vivos.append(a)
            except Exception:
                continue
        if vivos:
            candidatos = vivos

    if not candidatos:
        candidatos = driver.find_elements(
            By.XPATH,
            "//a[@id='video-title' or @id='video-title-link']"
            "[not(ancestor::ytd-ad-slot-renderer) and not(ancestor::ytd-promoted-video-renderer)]"
        )
    if not candidatos:
        print("⚠️ No encontré resultados orgánicos en YouTube.")
        return False

    objetivo = random.choice(candidatos)
    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", objetivo)
    time.sleep(random.uniform(0.3, 0.8))
    objetivo.click()
    return True

def youtube_skip_preroll_if_any(driver, max_wait_seconds=20):
    start = time.time()
    while time.time() - start < max_wait_seconds:
        try:
            ad_showing = driver.find_elements(By.CSS_SELECTOR, ".ad-showing, .ytp-ad-player-overlay, .ytp-ad-module")
            if ad_showing:
                skip_btn = WebDriverWait(driver, 2).until(EC.element_to_be_clickable((
                    By.XPATH,
                    "//button[contains(@class,'ytp-ad-skip-button') or contains(@class,'ytp-ad-skip-button-modern') "
                    "or contains(., 'Saltar') or contains(., 'Skip')]"
                )))
                try: skip_btn.click()
                except Exception: driver.execute_script("arguments[0].click();", skip_btn)
                time.sleep(1.0)
                break
        except TimeoutException:
            time.sleep(0.5)

# ========== Twitter/X (email + password) ==========
def is_twitter_logged_in(driver, timeout=6):
    driver.get("https://twitter.com/home")
    aceptar_cookies(driver); driver.execute_script("window.scrollBy(0,1);"); aceptar_cookies(driver)
    try:
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located((By.XPATH, "//div[@data-testid='primaryColumn']"))
        )
        print("✅ Ya estás logueado en Twitter/X (sesión activa).")
        return True
    except TimeoutException:
        return False

def login_twitter_con_email_password(driver):
    """
    Login en Twitter/X con email (GMAIL_USER) y password (GMAIL_PASSWORD).
    Si aparece el paso extra de 'teléfono o nombre de usuario', envía TWITTER_USERNAME (sin @).
    """
    driver.get("https://twitter.com/i/flow/login")
    aceptar_cookies(driver); driver.execute_script("window.scrollBy(0,1);"); aceptar_cookies(driver)
    time.sleep(1.2)

    try:
        # 1) Email / usuario inicial
        user_in = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.XPATH, "//input[@name='text' or @autocomplete='username']"))
        )
        user_in.clear(); user_in.send_keys(GMAIL_USER); user_in.send_keys(Keys.ENTER)
        print("📧 Email enviado"); time.sleep(1.0)

        # 2) Paso extra (teléfono/usuario) si no aparece password de inmediato
        try:
            WebDriverWait(driver, 4).until(
                EC.presence_of_element_located((By.XPATH, "//input[@name='password' or @type='password']"))
            )
            print("➡️ Password solicitado directamente.")
        except TimeoutException:
            sanitized_username = TWITTER_USERNAME.lstrip("@").strip()
            try:
                extra_in = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.XPATH, "//input[@name='text' or @data-testid='ocfEnterTextTextInput']"))
                )
                extra_in.clear(); extra_in.send_keys(sanitized_username); extra_in.send_keys(Keys.ENTER)
                print(f"🧩 Paso extra enviado con usuario: {sanitized_username}")
                time.sleep(1.0)
            except TimeoutException:
                print("⚠️ No apareció el campo del paso extra; continuando…")

        # 3) Contraseña
        pw_in = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.XPATH, "//input[@name='password' or @type='password']"))
        )
        pw_in.clear(); pw_in.send_keys(GMAIL_PASSWORD)
        try:
            login_btn = driver.find_element(
                By.XPATH, "//span[normalize-space(text())='Iniciar sesión' or normalize-space(text())='Log in']/ancestor::*[@role='button'][1]"
            )
            driver.execute_script("arguments[0].click();", login_btn)
        except NoSuchElementException:
            pw_in.send_keys(Keys.ENTER)

        print("🔑 Contraseña enviada"); time.sleep(1.5)

        # Challenge/2FA
        if "challenge" in (driver.current_url or ""):
            print("⚠️ Challenge/2FA detectado. Completa manualmente una vez; quedará la sesión en el perfil.")
            return False

        # Timeline
        WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.XPATH, "//div[@data-testid='primaryColumn']"))
        )
        print("✅ Sesión iniciada correctamente en Twitter/X.")
        return True

    except Exception as e:
        print(f"❌ Error en login Twitter email/password: {e}")
        return False

def navegar_twitter(driver):
    driver.get("https://twitter.com/home")
    aceptar_cookies(driver)
    driver.execute_script("window.scrollBy(0,1);")  # trigger cookies
    aceptar_cookies(driver)
    try:
        # 🔧 Solo hacer scroll (sin abrir tweets)
        for _ in range(random.randint(2, 5)):
            driver.execute_script("window.scrollBy(0, document.body.scrollHeight * 0.5);")
            print("⬇️ Scroll en Twitter/X")
            time.sleep(1.0)  # DEBUG DELAY
        print("🐦 Scroll en Twitter/X completado (sin abrir tweets).")
    except Exception as e:
        print(f"⚠️ Error scroll Twitter/X: {e}")

# ========== Dispatcher principal ==========
def ejecutar_accion_browser(info, driver):
    try:
        tipo = info.get("tipo", "")
        if tipo == "mirar_youtube":
            query = info.get("busqueda", "noticias actuales")
            driver.get(f"https://www.youtube.com/results?search_query={query.replace(' ', '+')}")
            aceptar_cookies(driver); driver.execute_script("window.scrollBy(0,1);"); aceptar_cookies(driver)
            time.sleep(1.0)
            if youtube_click_random_organic_result(driver, only_live=False):
                youtube_skip_preroll_if_any(driver, max_wait_seconds=25)
            else:
                print("⚠️ Sin resultados orgánicos en YouTube.")

        elif tipo == "buscar_google":
            termino = info.get("termino", "").strip() or random.choice(
                ["últimas noticias tecnología", "ciberseguridad", "inteligencia artificial hoy"]
            )
            driver.get("https://www.google.com/search?q=" + termino.replace(' ', '+'))
            aceptar_cookies(driver); driver.execute_script("window.scrollBy(0,1);"); aceptar_cookies(driver)
            time.sleep(1.0)

            candidatos = driver.find_elements(By.CSS_SELECTOR, "div.g a, div#search a")
            enlaces_validos = []
            for a in candidatos:
                href = a.get_attribute('href') or ""
                if not href.startswith("http"): continue
                if any(p in href for p in [
                    "google.", "webcache.googleusercontent", "policies.google", "support.google",
                    "maps.google", "accounts.google", "translate.google", "consent.google"
                ]): continue
                enlaces_validos.append(href)

            top = enlaces_validos[:random.randint(5, 8)]
            if top:
                destino = random.choice(top)
                print(f"🔗 Clic aleatorio en: {destino}")
                driver.get(destino)
                aceptar_cookies(driver); driver.execute_script("window.scrollBy(0,1);"); aceptar_cookies(driver)
                time.sleep(random.randint(3, 6))
            else:
                print("⚠️ No encontré resultados orgánicos válidos en Google.")

        elif tipo == "abrir_url":
            url = info.get("url", "https://www.bbc.com/mundo")
            driver.get(url)
            aceptar_cookies(driver); driver.execute_script("window.scrollBy(0,1);"); aceptar_cookies(driver)
            time.sleep(1.0)

        elif tipo == "revisar_correo":
            driver.get("https://accounts.google.com/signin/v2/identifier?service=mail")
            aceptar_cookies(driver); driver.execute_script("window.scrollBy(0,1);"); aceptar_cookies(driver)
            try:
                WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.ID, "identifierId")))
                iu = driver.find_element(By.ID, "identifierId")
                iu.clear(); iu.send_keys(GMAIL_USER); iu.send_keys(Keys.ENTER)
                print("✅ Usuario Gmail introducido")
                WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.NAME, "Passwd")))
                pw = driver.find_element(By.NAME, "Passwd")
                pw.clear(); pw.send_keys(GMAIL_PASSWORD); pw.send_keys(Keys.ENTER)
                print("🔑 Contraseña Gmail introducida")
                WebDriverWait(driver, 25).until(EC.presence_of_element_located((By.CSS_SELECTOR, "tr.zA")))
                aceptar_cookies(driver)
                driver.find_elements(By.CSS_SELECTOR, "tr.zA")[0].click()
                print("📬 Primer correo abierto")
            except Exception as e:
                print("❌ Error al revisar el correo:", e)

        elif tipo == "ver_streaming":
            busqueda = random.choice([
                "gaming en vivo", "noticias en vivo", "música en vivo",
                "just chatting live", "esports live", "programación en vivo"
            ])
            driver.get(f"https://www.youtube.com/results?search_query={busqueda.replace(' ', '+')}&sp=EgJAAQ%253D%253D")
            aceptar_cookies(driver); driver.execute_script("window.scrollBy(0,1);"); aceptar_cookies(driver)
            time.sleep(1.0)
            if youtube_click_random_organic_result(driver, only_live=True):
                youtube_skip_preroll_if_any(driver, max_wait_seconds=25)
            else:
                print("⚠️ No encontré directos orgánicos en YouTube.")

        elif tipo == "usar_twitter":
            if not is_twitter_logged_in(driver, timeout=5):
                if not login_twitter_con_email_password(driver):
                    print("⚠️ No se pudo iniciar sesión (quizá challenge/2FA).")
                    return
            navegar_twitter(driver)

    except Exception as e:
        print("❌ Error acción navegador:", e)

def simular_actividad(driver, delay):
    start = time.time()
    while time.time() - start < delay:
        if random.choice([True, False]):
            distancia = random.randint(120, 360)
            driver.execute_script(f"window.scrollBy(0, {distancia});")
            print(f"⬇️ Scroll {distancia}px")
        time.sleep(random.uniform(2, 5))

# ========== MAIN ==========
if __name__ == "__main__":
    fin = datetime.now() + timedelta(seconds=DURACION_TOTAL_SEGUNDOS)

    # --- Detectar Chrome y versión ---
    chrome_exe = get_chrome_exe()
    major = get_chrome_major(chrome_exe)
    print(f"🔍 Chrome detectado: {chrome_exe} | versión mayor: {major}")

    # --- Opciones Chrome ---
    options = uc.ChromeOptions()
    # Establecer binario (también pasamos browser_executable_path abajo)
    options.binary_location = chrome_exe
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument(f"--user-data-dir={PROFILE_DIR}")  # PERFIL PERSISTENTE

    # --- Crear driver alineado con tu versión de Chrome ---
    driver = uc.Chrome(
        version_main=major,               # None = uc detecta la versión automáticamente
        options=options,
        browser_executable_path=chrome_exe  # soporta portátil o instalación estándar
        # No pasamos driver_executable_path: uc se encarga de descargar el correcto
    )

    try:
        while datetime.now() < fin:
            print(f"🕒 Nueva acción ({datetime.now().strftime('%H:%M:%S')})")
            accion = obtener_accion_json_llm() or generar_accion_fallback()
            print("🔎 Acción decidida:", accion)
            ejecutar_accion_browser(accion, driver)
            delay = accion.get("delay", random.randint(8, 10))
            print(f"⏳ Simulando actividad {delay}s…")
            simular_actividad(driver, delay)
    finally:
        driver.quit()
