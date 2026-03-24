#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agenteadminavanzado.py — Orquestador Avanzado del Agente Administrador de Red

Flujo:
  1. Arranca las VMs Linux configuradas (VirtualBox, Hyper-V o VMware)
  2. Espera a que SSH esté disponible en cada VM (sondeo de puerto 22)
  3. Ejecuta AgenteAdminDeRed.py en la VM admin vía SSH con la duración indicada
  4. Al terminar, opcionalmente apaga las VMs

Modos de funcionamiento (mismo esquema que agentegameravanzado.py):
  - ciclico      : repite N sesiones del agente admin
  - secuencia    : ejecuta una lista de sesiones con duración variable
  - tiempo_total : duración total y distribución porcentual (si hay un agente mixto)

Uso rápido:
  python agenteadminavanzado.py
  MODO=ciclico CICLOS=3 DURACION_ADMIN_S=600 python agenteadminavanzado.py
  MODO=tiempo_total TIEMPO_TOTAL_S=3600 python agenteadminavanzado.py
  RUN_DURATION_S=900 python agenteadminavanzado.py

Variables de entorno clave:
  MODO                 ciclico | secuencia | tiempo_total  (default: ciclico)
  CICLOS               número de repeticiones en modo ciclico (default: 2)
  DURACION_ADMIN_S     segundos por turno admin (default: 300)
  PAUSA_ENTRE_S        pausa entre sesiones (default: 30)
  TIEMPO_TOTAL_S       duración total en modo tiempo_total (default: 3600)
  TURNO_S              tamaño de cada turno en modo tiempo_total (default: 900)
  APAGAR_VMS_AL_FINAL  1 para apagar VMs al terminar (default: 0)
  SUBIR_SCRIPT         1 para copiar AgenteAdminDeRed.py a la VM antes de ejecutar (default: 0)
  HIPERVISOR           virtualbox | hyperv | vmware (default: virtualbox)
"""

import os
import sys
import time
import signal
import socket
import threading
import subprocess
from datetime import datetime, timedelta

import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException

# ══════════════════════════════════════════════════════════
#  CONFIGURACIÓN DE VMs
# ══════════════════════════════════════════════════════════

# Lista de todas las VMs que deben estar activas durante la sesión.
# El agente admin se ejecutará en la primera VM marcada como admin=True.
#
# Formato:
#   {
#     "vm_name"  : nombre en VirtualBox / Hyper-V / VMware (string exacto),
#     "host"     : IP o hostname accesible desde Windows,
#     "port"     : puerto SSH (default 22),
#     "user"     : usuario SSH,
#     "password" : contraseña SSH (None si usas clave),
#     "keyfile"  : ruta a clave privada en Windows (None si usas contraseña),
#     "admin"    : True → aquí se ejecuta AgenteAdminDeRed.py,
#   }
#
# ⚠️ Edita esta lista antes de usar el script.
VMS = [
    {
        # ── VM 1: máquina administrador (ejecuta AgenteAdminDeRed.py) ──
        "vm_name" : os.environ.get("VM_ADMIN_NAME",  "kali-linux-2023.1-virtualbox-amd64"),
        "host"    : os.environ.get("VM_ADMIN_HOST",  "10.10.0.1"),
        "port"    : int(os.environ.get("VM_ADMIN_PORT", "22")),
        "user"    : os.environ.get("VM_ADMIN_USER",  "kali"),
        "password": os.environ.get("VM_ADMIN_PASS",  "kali") or None,
        "keyfile" : os.environ.get("VM_ADMIN_KEY",   None) or None,
        "admin"   : True,
    },
    {
        # ── VM 2: servidor objetivo 1 ──
        "vm_name" : os.environ.get("VM_SRV1_NAME",   "kali-linux-2023.1-virtualbox-amd6_2"),
        "host"    : os.environ.get("VM_SRV1_HOST",   "10.10.0.2"),
        "port"    : int(os.environ.get("VM_SRV1_PORT","22")),
        "user"    : os.environ.get("VM_SRV1_USER",   "kali"),
        "password": os.environ.get("VM_SRV1_PASS",   "kali") or None,
        "keyfile" : os.environ.get("VM_SRV1_KEY",    None) or None,
        "admin"   : False,
    },
    {
        # ── VM 3: servidor objetivo 2 ──
        "vm_name" : os.environ.get("VM_SRV2_NAME",   "kali-linux-2023.1-virtualbox-amd6_3"),
        "host"    : os.environ.get("VM_SRV2_HOST",   "10.10.0.3"),
        "port"    : int(os.environ.get("VM_SRV2_PORT","22")),
        "user"    : os.environ.get("VM_SRV2_USER",   "kali"),
        "password": os.environ.get("VM_SRV2_PASS",   "kali") or None,
        "keyfile" : os.environ.get("VM_SRV2_KEY",    None) or None,
        "admin"   : False,
    },
]

# ══════════════════════════════════════════════════════════
#  CONFIGURACIÓN DEL AGENTE ADMIN REMOTO
# ══════════════════════════════════════════════════════════

# Ruta del script en la VM admin (Linux)
RUTA_SCRIPT_REMOTO = os.environ.get("RUTA_SCRIPT_REMOTO", "/home/kali/AgenteAdminDeRed.py")

# Ruta local del script (para subirlo si SUBIR_SCRIPT=1)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUTA_SCRIPT_LOCAL = os.path.join(BASE_DIR, "AgenteAdminDeRed.py")

# Directorio de trabajo en la VM admin
WORK_DIR_REMOTO = os.environ.get("WORK_DIR_REMOTO", "/home/kali")

# Subir el script antes de ejecutar (útil si la VM está limpia)
SUBIR_SCRIPT = os.environ.get("SUBIR_SCRIPT", "0") == "1"

# ══════════════════════════════════════════════════════════
#  CONFIGURACIÓN DEL ORQUESTADOR
# ══════════════════════════════════════════════════════════

MODO             = os.environ.get("MODO", "ciclico")
CICLOS           = int(os.environ.get("CICLOS",           "2"))
DURACION_ADMIN_S = int(os.environ.get("DURACION_ADMIN_S", "300"))
PAUSA_ENTRE_S    = int(os.environ.get("PAUSA_ENTRE_S",    "30"))

TIEMPO_TOTAL_S   = int(os.environ.get("TIEMPO_TOTAL_S",   "3600"))
TURNO_S          = int(os.environ.get("TURNO_S",          "900"))

APAGAR_VMS_AL_FINAL = os.environ.get("APAGAR_VMS_AL_FINAL", "1") == "1"

# ══════════════════════════════════════════════════════════
#  CONFIGURACIÓN DEL HIPERVISOR
# ══════════════════════════════════════════════════════════

HIPERVISOR = os.environ.get("HIPERVISOR", "virtualbox").lower()

# Ruta a VBoxManage (Windows)
VBOXMANAGE = os.environ.get("VBOXMANAGE", r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")

# Ruta a vmrun (VMware Workstation)
VMRUN = os.environ.get("VMRUN", r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")

# Timeout máximo esperando que la VM arranque SSH (segundos)
VM_BOOT_TIMEOUT = int(os.environ.get("VM_BOOT_TIMEOUT", "120"))

# Intervalo de sondeo SSH durante arranque (segundos)
VM_POLL_INTERVAL = int(os.environ.get("VM_POLL_INTERVAL", "5"))

# ══════════════════════════════════════════════════════════
#  MODO SECUENCIA (editar si se usa MODO=secuencia)
# ══════════════════════════════════════════════════════════

SECUENCIA = [
    {"duracion": 600},
    {"duracion": 900},
    {"duracion": 600},
]

# ══════════════════════════════════════════════════════════
#  CONTROL DE SEÑALES
# ══════════════════════════════════════════════════════════

_sesion_ssh_activa: "paramiko.Channel | None" = None
_stop_event = threading.Event()


def _handler_sigint(sig, frame):
    global _sesion_ssh_activa
    print("\n[Orquestador] Ctrl+C detectado. Deteniendo agente remoto...")
    _stop_event.set()
    if _sesion_ssh_activa and not _sesion_ssh_activa.closed:
        try:
            _sesion_ssh_activa.send("\x03")  # Ctrl+C al proceso remoto
            time.sleep(1)
            _sesion_ssh_activa.close()
        except Exception:
            pass
    sys.exit(0)


signal.signal(signal.SIGINT, _handler_sigint)

# ══════════════════════════════════════════════════════════
#  UTILIDADES
# ══════════════════════════════════════════════════════════

def _segundos_a_hms(s: int) -> str:
    h, rem = divmod(int(s), 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {sec}s"
    if m:
        return f"{m}m {sec}s"
    return f"{sec}s"


def _banner(turno: int, total: int, duracion: int, inicio: datetime):
    fin = inicio + timedelta(seconds=duracion)
    print()
    print("=" * 60)
    print(f"  Turno {turno}/{total}  |  Agente: ADMIN")
    print(f"  Duración: {_segundos_a_hms(duracion)}")
    print(f"  Inicio:   {inicio.strftime('%H:%M:%S')}  →  Fin: {fin.strftime('%H:%M:%S')}")
    print("=" * 60)


def _pausa(segundos: int):
    if segundos <= 0:
        return
    print(f"\n[Orquestador] Pausa de {segundos}s antes del siguiente turno...")
    for restante in range(segundos, 0, -5):
        print(f"  {restante}s restantes...", end="\r")
        time.sleep(min(5, restante))
    print()


def _ssh_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

# ══════════════════════════════════════════════════════════
#  GESTIÓN DE VMs
# ══════════════════════════════════════════════════════════

def _vm_estado_vbox(vm_name: str) -> str:
    """Devuelve 'running', 'poweroff', 'saved', etc. Vacío si error."""
    try:
        r = subprocess.run(
            [VBOXMANAGE, "showvminfo", vm_name, "--machinereadable"],
            capture_output=True, text=True, timeout=15
        )
        for line in r.stdout.splitlines():
            if line.startswith("VMState="):
                return line.split("=", 1)[1].strip('"').lower()
    except Exception as e:
        print(f"  [VM] Error consultando estado de '{vm_name}': {e}")
    return ""


def _vm_start_vbox(vm_name: str) -> bool:
    estado = _vm_estado_vbox(vm_name)
    if estado == "running":
        print(f"  [VM] '{vm_name}' ya está en ejecución.")
        return True
    print(f"  [VM] Iniciando '{vm_name}' (VirtualBox headless)...")
    try:
        r = subprocess.run(
            [VBOXMANAGE, "startvm", vm_name, "--type", "gui"],
            capture_output=True, text=True, timeout=60
        )
        if r.returncode == 0:
            print(f"  [VM] '{vm_name}' arrancada.")
            return True
        else:
            print(f"  [VM] Error al iniciar '{vm_name}': {r.stderr.strip()}")
            return False
    except FileNotFoundError:
        print(f"  [VM] VBoxManage no encontrado en: {VBOXMANAGE}")
        print("       Edita VBOXMANAGE en el script o usa la variable de entorno VBOXMANAGE.")
        return False
    except Exception as e:
        print(f"  [VM] Excepción al iniciar '{vm_name}': {e}")
        return False


def _vm_stop_vbox(vm_name: str):
    print(f"  [VM] Apagando '{vm_name}' (acpi)...")
    try:
        subprocess.run(
            [VBOXMANAGE, "controlvm", vm_name, "acpipowerbutton"],
            capture_output=True, timeout=15
        )
    except Exception as e:
        print(f"  [VM] Error al apagar '{vm_name}': {e}")


def _vm_start_hyperv(vm_name: str) -> bool:
    try:
        r = subprocess.run(
            ["powershell", "-Command",
             f"$vm = Get-VM -Name '{vm_name}' -ErrorAction Stop; "
             f"if ($vm.State -ne 'Running') {{ Start-VM -Name '{vm_name}' }}; "
             f"Write-Output $vm.State"],
            capture_output=True, text=True, timeout=60
        )
        if r.returncode == 0:
            print(f"  [VM] '{vm_name}' Hyper-V iniciada/ya corriendo.")
            return True
        else:
            print(f"  [VM] Error Hyper-V: {r.stderr.strip()}")
            return False
    except Exception as e:
        print(f"  [VM] Excepción Hyper-V '{vm_name}': {e}")
        return False


def _vm_stop_hyperv(vm_name: str):
    try:
        subprocess.run(
            ["powershell", "-Command", f"Stop-VM -Name '{vm_name}' -Force"],
            capture_output=True, timeout=30
        )
    except Exception as e:
        print(f"  [VM] Error apagando Hyper-V '{vm_name}': {e}")


def _vm_start_vmware(vm_name: str) -> bool:
    """vm_name debe ser la ruta al .vmx para VMware."""
    try:
        r = subprocess.run(
            [VMRUN, "start", vm_name, "nogui"],
            capture_output=True, text=True, timeout=60
        )
        if r.returncode == 0:
            print(f"  [VM] '{vm_name}' VMware iniciada.")
            return True
        else:
            print(f"  [VM] Error VMware: {r.stderr.strip()}")
            return False
    except Exception as e:
        print(f"  [VM] Excepción VMware '{vm_name}': {e}")
        return False


def _vm_stop_vmware(vm_name: str):
    try:
        subprocess.run([VMRUN, "stop", vm_name, "soft"], capture_output=True, timeout=30)
    except Exception as e:
        print(f"  [VM] Error apagando VMware '{vm_name}': {e}")


def start_vm(vm: dict) -> bool:
    name = vm["vm_name"]
    if HIPERVISOR == "hyperv":
        return _vm_start_hyperv(name)
    elif HIPERVISOR == "vmware":
        return _vm_start_vmware(name)
    else:
        return _vm_start_vbox(name)


def stop_vm(vm: dict):
    name = vm["vm_name"]
    if HIPERVISOR == "hyperv":
        _vm_stop_hyperv(name)
    elif HIPERVISOR == "vmware":
        _vm_stop_vmware(name)
    else:
        _vm_stop_vbox(name)


def wait_for_ssh(vm: dict) -> bool:
    host = vm["host"]
    port = vm["port"]
    t0 = time.time()
    print(f"  [SSH] Esperando SSH en {host}:{port} (timeout={VM_BOOT_TIMEOUT}s)...", end="", flush=True)
    while time.time() - t0 < VM_BOOT_TIMEOUT:
        if _ssh_port_open(host, port):
            elapsed = int(time.time() - t0)
            print(f" listo en {elapsed}s")
            return True
        print(".", end="", flush=True)
        time.sleep(VM_POLL_INTERVAL)
    print(f" TIMEOUT ({VM_BOOT_TIMEOUT}s)")
    return False


def arrancar_todas_las_vms() -> bool:
    """Arranca todas las VMs y espera SSH. Devuelve True si todas están listas."""
    print("\n[VMs] Iniciando máquinas virtuales...")
    ok_total = True

    for vm in VMS:
        print(f"\n  [VM] Procesando: {vm['vm_name']} ({vm['host']})")
        if not start_vm(vm):
            print(f"  [VM] ⚠️  No se pudo iniciar '{vm['vm_name']}'. Continuando de todos modos.")
            ok_total = False
            continue
        # Pequeña espera inicial para que el hipervisor registre el arranque
        time.sleep(3)
        if not wait_for_ssh(vm):
            print(f"  [VM] ⚠️  SSH no disponible en '{vm['vm_name']}' tras {VM_BOOT_TIMEOUT}s.")
            ok_total = False

    if ok_total:
        print("\n[VMs] Todas las VMs están listas.")
    else:
        print("\n[VMs] ⚠️  Algunas VMs no respondieron. Se intentará continuar igualmente.")

    return ok_total


def apagar_todas_las_vms():
    print("\n[VMs] Apagando máquinas virtuales...")
    for vm in VMS:
        stop_vm(vm)
    print("[VMs] Apagado enviado a todas las VMs.")

# ══════════════════════════════════════════════════════════
#  EJECUCIÓN REMOTA DEL AGENTE ADMIN
# ══════════════════════════════════════════════════════════

def _get_admin_vm() -> "dict | None":
    for vm in VMS:
        if vm.get("admin"):
            return vm
    return None


def _ssh_connect(vm: dict) -> "paramiko.SSHClient | None":
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    keyfile = vm.get("keyfile")
    password = vm.get("password")
    try:
        client.connect(
            vm["host"],
            port=vm["port"],
            username=vm["user"],
            password=password,
            key_filename=keyfile,
            timeout=10,
            allow_agent=(password is None),
            look_for_keys=(password is None),
        )
        return client
    except AuthenticationException:
        print(f"  [SSH] Error de autenticación en {vm['host']}. Revisa usuario/contraseña/clave.")
    except SSHException as e:
        print(f"  [SSH] Error SSH en {vm['host']}: {e}")
    except Exception as e:
        print(f"  [SSH] No se pudo conectar a {vm['host']}: {e}")
    return None


def _subir_script(client: paramiko.SSHClient):
    print(f"  [SFTP] Subiendo {RUTA_SCRIPT_LOCAL} → {RUTA_SCRIPT_REMOTO}...")
    try:
        sftp = client.open_sftp()
        sftp.put(RUTA_SCRIPT_LOCAL, RUTA_SCRIPT_REMOTO)
        sftp.close()
        # También subir hosts.yaml si existe
        hosts_yaml = os.path.join(BASE_DIR, "hosts.yaml")
        if os.path.isfile(hosts_yaml):
            remote_hosts = f"{WORK_DIR_REMOTO}/hosts.yaml"
            sftp2 = client.open_sftp()
            sftp2.put(hosts_yaml, remote_hosts)
            sftp2.close()
            print(f"  [SFTP] hosts.yaml subido a {remote_hosts}")
        print(f"  [SFTP] Script subido correctamente.")
    except Exception as e:
        print(f"  [SFTP] Error subiendo script: {e}")


def ejecutar_agente_admin_remoto(duracion: int) -> int:
    """
    Conecta por SSH a la VM admin, ejecuta AgenteAdminDeRed.py con RUN_DURATION_S=duracion
    y espera a que termine. Devuelve el código de salida (0 = OK).
    """
    global _sesion_ssh_activa

    vm = _get_admin_vm()
    if vm is None:
        print("[Admin] ERROR: No hay ninguna VM marcada como admin=True en VMS.")
        return -1

    print(f"\n[Admin] Conectando a VM admin: {vm['user']}@{vm['host']}:{vm['port']}")
    client = _ssh_connect(vm)
    if client is None:
        return -1

    try:
        if SUBIR_SCRIPT:
            _subir_script(client)

        # Comando remoto: ejecutar el agente con la duración solicitada
        cmd = (
            f"cd {WORK_DIR_REMOTO} && "
            f"RUN_DURATION_S={duracion} python3 {RUTA_SCRIPT_REMOTO} 2>&1"
        )
        print(f"[Admin] Ejecutando en remoto (RUN_DURATION_S={duracion}s):")
        print(f"        {cmd}")
        print(f"[Admin] Duración prevista: {_segundos_a_hms(duracion)}")
        print("-" * 60)

        # Canal interactivo para capturar salida en tiempo real
        transport = client.get_transport()
        chan = transport.open_session()
        chan.set_combine_stderr(True)
        chan.exec_command(cmd)
        _sesion_ssh_activa = chan

        # Leer salida en tiempo real mientras el canal esté abierto
        while not chan.exit_status_ready():
            if _stop_event.is_set():
                chan.send("\x03")
                break
            if chan.recv_ready():
                data = chan.recv(4096).decode(errors="replace")
                print(data, end="", flush=True)
            else:
                time.sleep(0.2)
        # Vaciar buffer restante
        while chan.recv_ready():
            data = chan.recv(4096).decode(errors="replace")
            print(data, end="", flush=True)

        exit_code = chan.recv_exit_status()
        chan.close()
        _sesion_ssh_activa = None

        print("-" * 60)
        if exit_code == 0:
            print(f"[Admin] Agente admin completado correctamente (exit=0).")
        else:
            print(f"[Admin] Agente admin terminó con código {exit_code}.")
        return exit_code

    except Exception as e:
        print(f"[Admin] Error durante ejecución remota: {e}")
        return -1
    finally:
        try:
            client.close()
        except Exception:
            pass

# ══════════════════════════════════════════════════════════
#  CONSTRUCCIÓN DE TURNOS
# ══════════════════════════════════════════════════════════

def _construir_turnos_tiempo_total() -> list:
    """
    En modo tiempo_total con un solo agente (admin), genera turnos de TURNO_S
    hasta cubrir TIEMPO_TOTAL_S.
    """
    restante = TIEMPO_TOTAL_S
    turnos = []
    while restante > 0:
        dur = min(TURNO_S, restante)
        turnos.append({"duracion": dur})
        restante -= dur
    print(f"[Orquestador] tiempo_total={_segundos_a_hms(TIEMPO_TOTAL_S)} | "
          f"turno={_segundos_a_hms(TURNO_S)} | turnos={len(turnos)}")
    return turnos


def construir_turnos() -> list:
    if MODO == "secuencia":
        return list(SECUENCIA)
    if MODO == "tiempo_total":
        return _construir_turnos_tiempo_total()
    # Modo cíclico: CICLOS repeticiones de DURACION_ADMIN_S
    return [{"duracion": DURACION_ADMIN_S} for _ in range(CICLOS)]

# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    turnos = construir_turnos()

    if not turnos:
        print("[Orquestador] ERROR: No hay turnos definidos.")
        sys.exit(1)

    total_s = sum(t["duracion"] for t in turnos) + PAUSA_ENTRE_S * max(0, len(turnos) - 1)

    print("=" * 60)
    print("  Orquestador Avanzado — Agente Administrador de Red")
    print("=" * 60)
    print(f"  Hipervisor:     {HIPERVISOR}")
    print(f"  Modo:           {MODO}")
    print(f"  Turnos:         {len(turnos)}")
    print(f"  Pausa entre:    {PAUSA_ENTRE_S}s")
    print(f"  Tiempo total:   ~{_segundos_a_hms(total_s)}")
    print(f"  Fin estimado:   {(datetime.now() + timedelta(seconds=total_s)).strftime('%H:%M:%S')}")
    print(f"  Script remoto:  {RUTA_SCRIPT_REMOTO}")
    print(f"  Subir script:   {'Sí' if SUBIR_SCRIPT else 'No'}")
    print(f"  Apagar VMs al final: {'Sí' if APAGAR_VMS_AL_FINAL else 'No'}")
    print()
    print("  VMs configuradas:")
    for vm in VMS:
        rol = " [ADMIN]" if vm.get("admin") else ""
        auth = f"key:{vm['keyfile']}" if vm.get("keyfile") else "password"
        print(f"    • {vm['vm_name']:20s}  {vm['user']}@{vm['host']}:{vm['port']}  ({auth}){rol}")
    print("=" * 60)

    # 1. Arrancar y esperar VMs
    arrancar_todas_las_vms()

    # 2. Ejecutar turnos
    for i, turno in enumerate(turnos, start=1):
        if _stop_event.is_set():
            break

        duracion = turno["duracion"]
        inicio   = datetime.now()

        _banner(i, len(turnos), duracion, inicio)
        ejecutar_agente_admin_remoto(duracion)

        if i < len(turnos) and not _stop_event.is_set():
            _pausa(PAUSA_ENTRE_S)

    # 3. Apagar VMs (si configurado)
    if APAGAR_VMS_AL_FINAL:
        apagar_todas_las_vms()

    print()
    print("=" * 60)
    print("  Sesión de administración completada.")
    print("=" * 60)
