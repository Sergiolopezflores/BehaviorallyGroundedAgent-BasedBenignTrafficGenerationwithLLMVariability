#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v2.6.py - v2.5 + tráfico fuera de SSH (ICMP/DNS/HTTP) desde pcadmin.

- Sin cambios en hosts.yaml.
- Objetivo: que en PCAP no todo sea SSHv2/TCP; añadir protocolos típicos de admin.

Uso:
  python3 v2.6.py
  RUN_DURATION_S=900 python3 v2.6.py
"""

import json, time, pathlib, concurrent.futures as cf
import socket, errno, sys, os, logging, yaml, paramiko, csv, datetime, html, random, struct, subprocess, urllib.request
from paramiko.ssh_exception import AuthenticationException, SSHException, NoValidConnectionsError, BadHostKeyException

INVENTORY_FILE = "hosts.yaml"
LOG_DIR = pathlib.Path("logs"); LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(filename="paramiko.log", level=logging.DEBUG)

# ---------------------------
# Ventana y sesiones
# ---------------------------
RUN_DURATION_S = int(os.environ.get("RUN_DURATION_S", "300"))

SESSION_IDLE_RANGE = (float(os.environ.get("SESSION_IDLE_MIN", "5")),
                      float(os.environ.get("SESSION_IDLE_MAX", "15")))

SESSION_CMDS_RANGE = (int(os.environ.get("SESSION_CMDS_MIN", "4")),
                      int(os.environ.get("SESSION_CMDS_MAX", "9")))

PULL_PROB = float(os.environ.get("PULL_PROB", "0.35"))
SYSLOG_PROB = float(os.environ.get("SYSLOG_PROB", "0.30"))

# ---------------------------
# Micro-interacciones PTY (de v2.5)
# ---------------------------
P_NAVIGATE = float(os.environ.get("P_NAVIGATE", "0.35"))
P_TYPO = float(os.environ.get("P_TYPO", "0.03"))
P_PARTIAL_READ = float(os.environ.get("P_PARTIAL_READ", "0.45"))
P_FOLLOW_SHORT = float(os.environ.get("P_FOLLOW_SHORT", "0.20"))
FOLLOW_TIMEOUT_RANGE = (float(os.environ.get("FOLLOW_MIN_S", "2.0")),
                        float(os.environ.get("FOLLOW_MAX_S", "4.0")))

PTY_TYPING_DELAY = (0.02, 0.10)
CMD_PAUSE = (0.4, 2.0)
STAGGER_MIN = 0.5
STAGGER_MAX = 4.0

# ---------------------------
# NUEVO: Tráfico fuera de SSH
# ---------------------------
P_ICMP = float(os.environ.get("P_ICMP", "0.65"))   # ping casi siempre
P_DNS  = float(os.environ.get("P_DNS",  "0.55"))   # queries DNS frecuentes
P_HTTP = float(os.environ.get("P_HTTP", "0.45"))   # intentos HTTP moderados

DNS_TIMEOUT = float(os.environ.get("DNS_TIMEOUT", "1.5"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "2.0"))
SYSLOG_PORT = 514

# SFTP
SFTP_RETRIES = 3
SFTP_BACKOFF = 1.5

ADMIN_COMMAND_POOLS = {
    "checks": ["ss -tunap", "ip -br a", "ip route", "df -h", "free -m", "uptime -p"],
    "service_ops": ["systemctl status nginx", "systemctl status rsyslog",
                    "systemctl restart rsyslog || true", "systemctl restart nginx || true"],
    "logs": ["journalctl -u nginx -n 200 --no-pager",
             "journalctl -p err -n 100 --no-pager",
             "dmesg | tail -n 80"],
    "config": ["cat /etc/hosts", "ls -la /etc", "stat /etc/hosts"],
    "maintenance": ["apt update -y || true", "apt upgrade -y || true"],
    "interactive_checks": ["systemctl is-active nginx || true",
                           "ss -tulpen | head -n 20",
                           "netstat -tulpen | head -n 20 || true"]
}

BASE_COMMANDS = [
    "hostnamectl --static || hostname",
    "uptime -p || uptime",
    "ip -br a || ip a",
    "ss -tulpen || netstat -tulpen || true",
    "df -h -x tmpfs -x devtmpfs || df -h || true",
    "free -m || true",
    "systemctl --failed || true",
    "journalctl -p err -n 100 --no-pager || true",
]

NAV_STEPS = [
    "pwd",
    "cd /var/log || true",
    "ls -la | head -n 40",
    "cd /etc || true",
    "ls -la | head -n 40",
    "pwd",
]

# Dominios “neutros” para forzar DNS (puedes cambiar)
DNS_DOMAINS = [
    "example.com", "example.org", "iana.org", "cloudflare.com",
    "python.org", "debian.org", "kernel.org"
]

def load_inventory(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not data or "hosts" not in data or not isinstance(data["hosts"], list):
        raise SystemExit("[ERROR] Inventario inválido: falta 'hosts' lista.")
    return data

def tcp_probe(ip, port=22, timeout=2.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(1.0)
            banner = ""
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except socket.timeout:
                pass
            return {"state": "OPEN", "banner": banner}
    except ConnectionRefusedError:
        return {"state": "REFUSED", "banner": ""}
    except socket.timeout:
        return {"state": "TIMEOUT", "banner": ""}
    except OSError as e:
        if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN, errno.ETIMEDOUT):
            return {"state": "UNREACHABLE", "banner": ""}
        return {"state": "ERROR", "banner": "", "error": str(e)}

def _expand_path(p):
    if not p: return None
    return os.path.abspath(os.path.expanduser(os.path.expandvars(p)))

def _connect_with_prefs(client, ip, port, user, password, keyfile, allow_agent, look_for_keys):
    client.connect(ip, port=port, username=user, password=password, key_filename=keyfile,
                   timeout=8, allow_agent=allow_agent, look_for_keys=look_for_keys, compress=True)

def pick_commands_for_host(host):
    cmds = []
    cmds.extend(random.sample(ADMIN_COMMAND_POOLS["checks"], k=2))
    if random.random() < 0.6: cmds.append(random.choice(ADMIN_COMMAND_POOLS["logs"]))
    if random.random() < 0.4: cmds.append(random.choice(ADMIN_COMMAND_POOLS["service_ops"]))
    if random.random() < 0.2: cmds.append(random.choice(ADMIN_COMMAND_POOLS["maintenance"]))
    if random.random() < 0.3: cmds.append(random.choice(ADMIN_COMMAND_POOLS["config"]))
    if random.random() < 0.5: cmds.append(random.choice(ADMIN_COMMAND_POOLS["interactive_checks"]))
    random.shuffle(cmds)
    return cmds or random.sample(BASE_COMMANDS, k=3)

def _sanitize_filename(s):
    return "".join(c for c in s if c.isalnum() or c in (' ', '.', '_', '-')).rstrip()

def _session_safe_id(session_id: str) -> str:
    return "".join(c for c in session_id if c.isalnum() or c in ('-', '_'))

def _maybe_typo(cmd: str) -> str:
    if not cmd or len(cmd) < 4: return cmd
    mode = random.choice(["swap", "drop", "replace", "insert"])
    s = list(cmd)
    i = random.randint(0, len(s)-2)
    if mode == "swap" and i+1 < len(s): s[i], s[i+1] = s[i+1], s[i]
    elif mode == "drop": s.pop(i)
    elif mode == "replace": s[i] = random.choice("abcdefghijklmnopqrstuvwxyz")
    elif mode == "insert": s.insert(i, random.choice("abcdefghijklmnopqrstuvwxyz"))
    return "".join(s)

def _is_loggy(cmd: str) -> bool:
    c = cmd.strip()
    return any(k in c for k in ["journalctl", "dmesg", "/var/log"])

def _partial_read_transform(cmd: str) -> str:
    c = cmd.strip()
    if c.startswith("journalctl"):
        if "-n " in c and random.random() < 0.5:
            return c
        return "journalctl -n 120 --no-pager | tail -n 80"
    if c.startswith("dmesg"):
        return "dmesg | tail -n 120 | head -n 80"
    if "cat /var/log" in c:
        return c.replace("cat ", "tail -n 120 ") + " | head -n 80"
    if "|" in c:
        return c + " | tail -n 80"
    return c + " | tail -n 120 | head -n 80"

def _follow_short_command(cmd: str) -> str:
    t = random.uniform(*FOLLOW_TIMEOUT_RANGE)
    if "journalctl" in cmd or "nginx" in cmd:
        return f"timeout {t:.1f} journalctl -f -n 20 --no-pager -u nginx || true"
    candidates = ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages", "/var/log/kern.log"]
    path = random.choice(candidates)
    return f"timeout {t:.1f} tail -f {path} 2>/dev/null || true"

def _build_command_sequence(cmds):
    final = []
    for cmd in cmds:
        if random.random() < P_NAVIGATE:
            final.extend(random.sample(NAV_STEPS, k=random.randint(1, 3)))
        cmd2 = _partial_read_transform(cmd) if (_is_loggy(cmd) and random.random() < P_PARTIAL_READ) else cmd
        if _is_loggy(cmd2) and random.random() < P_FOLLOW_SHORT:
            final.append(cmd2)
            final.append(_follow_short_command(cmd2))
            continue
        if random.random() < P_TYPO:
            final.append(_maybe_typo(cmd2))
            final.append("\x03")  # Ctrl+C
            final.append(cmd2)
        else:
            final.append(cmd2)
    return final

def run_interactive_commands(client, cmds, timeout=90):
    try:
        chan = client.invoke_shell()
        chan.settimeout(timeout)
    except Exception:
        out_all = ""
        for cmd in cmds:
            try:
                _, stdout, stderr = client.exec_command(cmd, timeout=25, get_pty=False)
                _ = stdout.channel.recv_exit_status()
                out_all += stdout.read().decode(errors="replace")
                out_all += stderr.read().decode(errors="replace")
            except Exception as ex:
                out_all += f"\n[ERR exec_fallback] {ex}"
        return out_all

    out_buf = ""
    actions = _build_command_sequence(cmds)

    def drain(seconds=1.8):
        nonlocal out_buf
        t0 = time.time()
        while time.time() - t0 < seconds:
            if chan.recv_ready():
                out_buf += chan.recv(4096).decode(errors="replace")
            else:
                time.sleep(0.05)

    try:
        for act in actions:
            if act == "\x03":
                chan.send("\x03")
                time.sleep(random.uniform(0.15, 0.6))
                drain(0.8)
                continue
            tosend = act + "\n"
            for ch in tosend:
                chan.send(ch)
                time.sleep(random.uniform(*PTY_TYPING_DELAY))
            time.sleep(random.uniform(*CMD_PAUSE))
            drain(1.7)
        time.sleep(0.2)
        while chan.recv_ready():
            out_buf += chan.recv(4096).decode(errors="replace")
    finally:
        try: chan.close()
        except Exception: pass

    MAX_OUT = 20000
    return out_buf if len(out_buf) <= MAX_OUT else out_buf[:MAX_OUT] + f"\n...TRUNCATED({len(out_buf)} bytes)..."

def sftp_get_with_retries(sftp, remote_path, local_path, retries=SFTP_RETRIES):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            sftp.get(remote_path, str(local_path))
            try:
                remote_size = sftp.stat(remote_path).st_size
                local_size = os.path.getsize(local_path)
                if remote_size == local_size:
                    return True, None
                last_err = f"size_mismatch remote={remote_size} local={local_size}"
            except Exception:
                return True, None
        except Exception as e:
            last_err = str(e)
            time.sleep(SFTP_BACKOFF * attempt)
    return False, last_err

def send_syslog_udp(collector_ip, message, port=SYSLOG_PORT):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(message.encode(), (collector_ip, port))
        s.close()
        return True
    except Exception:
        return False

# ---------------------------
# NUEVO: Generación de tráfico fuera de SSH
# ---------------------------
def _read_resolv_nameserver():
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except Exception:
        pass
    return None

def _dns_build_query_a(qname: str, qid: int) -> bytes:
    # Header: ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # recursion desired
    # QNAME: labels
    parts = qname.strip(".").split(".")
    qname_bytes = b"".join(struct.pack("!B", len(p)) + p.encode() for p in parts) + b"\x00"
    qtype_qclass = struct.pack("!HH", 1, 1)  # A, IN
    return header + qname_bytes + qtype_qclass

def generate_dns_traffic():
    ns = _read_resolv_nameserver()
    if not ns:
        # fallback: resolver del sistema (puede no generar UDP si cacheado, pero suele generar algo)
        try:
            socket.getaddrinfo(random.choice(DNS_DOMAINS), 80)
            return {"dns": "getaddrinfo", "ok": True}
        except Exception as e:
            return {"dns": "getaddrinfo", "ok": False, "err": str(e)}

    qname = random.choice(DNS_DOMAINS)
    qid = random.randint(0, 65535)
    pkt = _dns_build_query_a(qname, qid)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(DNS_TIMEOUT)
        s.sendto(pkt, (ns, 53))
        _ = s.recvfrom(512)  # respuesta
        s.close()
        return {"dns": "udp53", "ns": ns, "qname": qname, "ok": True}
    except Exception as e:
        try: s.close()
        except Exception: pass
        return {"dns": "udp53", "ns": ns, "qname": qname, "ok": False, "err": str(e)}

def generate_icmp_ping(ip: str):
    # 1 ping rápido. Si no hay permisos/capabilities, fallará y lo registramos.
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.5
        )
        return {"icmp": "ping", "ip": ip, "ok": (r.returncode == 0)}
    except Exception as e:
        return {"icmp": "ping", "ip": ip, "ok": False, "err": str(e)}

def generate_http_check(ip: str):
    # Intento HTTP simple. Aunque no haya servidor, genera TCP a 80 (SYN/RST).
    url = f"http://{ip}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "admin-sim/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            _ = resp.read(256)  # leer un poco para generar payload
            return {"http": "get", "url": url, "ok": True, "code": int(code)}
    except Exception as e:
        # Fallback: al menos conectar TCP (si urllib falla antes por DNS etc.)
        try:
            with socket.create_connection((ip, 80), timeout=HTTP_TIMEOUT):
                pass
            return {"http": "tcp80", "url": url, "ok": True, "code": None}
        except Exception as e2:
            return {"http": "get", "url": url, "ok": False, "err": str(e), "err2": str(e2)}

def run_out_of_ssh_checks(host_ip: str, host_name: str, session_id: str):
    """
    Genera ICMP/DNS/HTTP desde pcadmin (fuera del túnel SSH).
    Devuelve lista de eventos para log.
    """
    events = []
    if random.random() < P_ICMP:
        events.append(generate_icmp_ping(host_ip))
    if random.random() < P_DNS:
        events.append(generate_dns_traffic())
    if random.random() < P_HTTP:
        events.append(generate_http_check(host_ip))
    if events:
        # añade contexto
        for ev in events:
            ev["ts"] = time.time()
            ev["host"] = host_name
            ev["session_id"] = session_id
    return events

# ---------------------------
# Sesión SSH + SFTP + syslog
# ---------------------------
def run_host_session(host, session_id: str, max_cmds: int, do_pulls: bool, do_syslog: bool):
    name = host.get("name", host["host"])
    ip = host["host"]
    user = host.get("user", "kali")
    port = int(host.get("port", 22))
    keyfile_raw = host.get("keyfile")
    keyfile = _expand_path(keyfile_raw) if keyfile_raw else None
    password = host.get("password")
    pulls = host.get("pull", [])
    allow_agent = host.get("allow_agent", True)
    look_for_keys = host.get("look_for_keys", True)

    simulate_failure_prob = float(host.get("simulate_failure_prob", 0.0))
    simulate_failure_service = host.get("simulate_failure_service", "nginx")
    syslog_collector = host.get("syslog_collector")
    provided_cmds = host.get("commands")

    result = {"host": name, "ip": ip, "ok": True, "errors": [], "precheck": None,
              "duration_s": None, "commands_executed": [], "session_id": session_id}
    t0 = time.time()

    probe = tcp_probe(ip, port, timeout=2.0)
    result["precheck"] = probe
    if probe["state"] != "OPEN":
        result["ok"] = False
        result["errors"].append({"precheck": probe})
        result["duration_s"] = round(time.time() - t0, 2)
        return result

    if keyfile and not os.path.exists(keyfile):
        result["errors"].append({"config": f"keyfile_not_found:{keyfile}"})
        keyfile = None
    if password:
        allow_agent = False
        look_for_keys = False

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        try:
            _connect_with_prefs(client, ip, port, user, password, keyfile, allow_agent, look_for_keys)
        except SSHException as e:
            if "Incorrect padding" in str(e):
                _connect_with_prefs(client, ip, port, user, password, keyfile, False, False)
            else:
                raise
    except Exception as e:
        result["ok"] = False
        result["errors"].append({"connect": type(e).__name__, "detail": str(e)})
        result["duration_s"] = round(time.time() - t0, 2)
        return result

    if provided_cmds and isinstance(provided_cmds, list) and provided_cmds:
        cmds_to_run = list(provided_cmds)
    else:
        cmds_to_run = pick_commands_for_host(host)

    if simulate_failure_prob and random.random() < simulate_failure_prob:
        check_cmd = f"systemctl is-active {simulate_failure_service} || true"
        restart_cmd = f"systemctl restart {simulate_failure_service} || true"
        cmds_to_run = [check_cmd, restart_cmd] + cmds_to_run
        result.setdefault("meta", {})["simulated_failure_injected"] = True

    if max_cmds and len(cmds_to_run) > max_cmds:
        random.shuffle(cmds_to_run)
        cmds_to_run = cmds_to_run[:max_cmds]

    log_file = LOG_DIR / f"{_sanitize_filename(name)}.jsonl"
    sess_tag = _session_safe_id(session_id)

    try:
        out_text = run_interactive_commands(client, cmds_to_run, timeout=120)
        with log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": time.time(), "host": name, "session_id": session_id,
                "commands": cmds_to_run, "stdout_snippet": out_text[:10000]
            }, ensure_ascii=False) + "\n")

        if pulls and do_pulls:
            try:
                sftp = client.open_sftp()
                local_dir = LOG_DIR / _sanitize_filename(name)
                local_dir.mkdir(parents=True, exist_ok=True)
                for remote in pulls:
                    base = pathlib.Path(remote).name
                    local = local_dir / f"{sess_tag}_{base}"
                    ok, err = sftp_get_with_retries(sftp, remote, local)
                    if ok:
                        with log_file.open("a", encoding="utf-8") as f:
                            f.write(json.dumps({
                                "ts": time.time(), "host": name, "session_id": session_id,
                                "sftp": f"pulled:{remote}->{local}"
                            }, ensure_ascii=False) + "\n")
                    else:
                        result["errors"].append({"sftp": f"{remote}", "error": err})
                sftp.close()
            except Exception as e:
                result["errors"].append({"sftp_open": str(e)})
    except Exception as e:
        result["errors"].append({"exec": str(e)})
    finally:
        client.close()
        result["duration_s"] = round(time.time() - t0, 2)

    if syslog_collector and do_syslog:
        msg = f"<14>1 {datetime.datetime.utcnow().isoformat()} admin-sim - - - Simulated log from {name} session={session_id}"
        try:
            send_syslog_udp(syslog_collector, msg)
            with log_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": time.time(), "host": name, "session_id": session_id,
                    "syslog_sent": f"to:{syslog_collector}"
                }, ensure_ascii=False) + "\n")
        except Exception as e:
            result["errors"].append({"syslog_send": str(e)})

    result["commands_executed"] = cmds_to_run
    return result

def run_host_sessions(host, stop_time: float, host_idx: int):
    results = []
    stagger = random.uniform(STAGGER_MIN, STAGGER_MAX) * (host_idx % 3)
    time.sleep(stagger)

    i = 0
    host_name = host.get("name", host.get("host", "host"))
    while time.time() < stop_time:
        i += 1
        session_id = f"{_sanitize_filename(host_name)}-{int(time.time())}-{i}"
        max_cmds = random.randint(*SESSION_CMDS_RANGE)

        # NUEVO: checks fuera de SSH para que salgan ICMP/DNS/HTTP en el PCAP
        events = run_out_of_ssh_checks(host.get("host"), host_name, session_id)
        if events:
            log_file = LOG_DIR / f"{_sanitize_filename(host_name)}.jsonl"
            with log_file.open("a", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")

        do_pulls = (random.random() < PULL_PROB)
        do_syslog = (random.random() < SYSLOG_PROB)

        r = run_host_session(host, session_id=session_id, max_cmds=max_cmds,
                             do_pulls=do_pulls, do_syslog=do_syslog)
        results.append(r)

        if time.time() < stop_time:
            time.sleep(random.uniform(*SESSION_IDLE_RANGE))

    return results

def write_reports(results):
    csv_path = LOG_DIR / "summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["session_id","host","ip","status","duration_s","errs","precheck_state","banner"])
        for r in results:
            status = "OK" if r["ok"] and not r["errors"] else ("WARN" if r["ok"] else "FAIL")
            pre = r.get("precheck", {}) or {}
            banner = pre.get("banner","")
            banner_snip = (banner[:60] + "…") if banner and len(banner) > 60 else banner
            w.writerow([r.get("session_id",""), r["host"], r["ip"], status, r["duration_s"],
                        len(r["errors"]), pre.get("state"), banner_snip])

    html_path = LOG_DIR / "summary.html"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for r in results:
        status = "OK" if r["ok"] and not r["errors"] else ("WARN" if r["ok"] else "FAIL")
        color = {"OK":"#16a34a","WARN":"#f59e0b","FAIL":"#ef4444"}.get(status, "#64748b")
        pre = r.get("precheck", {}) or {}
        banner = html.escape(pre.get("banner",""))
        banner_snip = (banner[:80] + "…") if banner and len(banner) > 80 else banner
        errs_cnt = len(r["errors"])
        details = html.escape(json.dumps(r["errors"], ensure_ascii=False, indent=2))
        jsonl_link = f"{_sanitize_filename(r['host'])}.jsonl"
        host_dir = f"{_sanitize_filename(r['host'])}/"
        sid = html.escape(r.get("session_id",""))
        rows.append(f"""
        <tr>
          <td style="font-family:monospace">{sid}</td>
          <td><b>{html.escape(r['host'])}</b></td>
          <td>{html.escape(r['ip'])}</td>
          <td><span style="color:{color};font-weight:600">{status}</span></td>
          <td style="text-align:right">{r['duration_s']}</td>
          <td style="text-align:right">{errs_cnt}</td>
          <td>{html.escape(pre.get('state',''))}</td>
          <td style="font-family:monospace">{banner_snip}</td>
          <td>
            <a href="{jsonl_link}">logs/{jsonl_link}</a>
            &nbsp;|&nbsp;<a href="{host_dir}">logs/{host_dir}</a>
            <details><summary>ver detalles</summary><pre>{details}</pre></details>
          </td>
        </tr>""")
    doc = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Resumen v2.6 (SSH + ICMP/DNS/HTTP)</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0b1020;color:#e5e7eb;margin:0;padding:24px}}
h1{{font-size:20px;margin:0 0 6px}}
small{{color:#94a3b8}}
table{{width:100%;border-collapse:collapse;margin-top:16px;background:#0f172a;border-radius:12px;overflow:hidden}}
th,td{{padding:10px 12px;border-bottom:1px solid #1f2937;vertical-align:top}}
th{{text-align:left;background:#111827;position:sticky;top:0}}
tr:hover td{{background:#0b1226}}
code,pre{{background:#0b1226;border:1px solid #1f2937;border-radius:8px;padding:8px;display:block;white-space:pre-wrap}}
a{{color:#60a5fa;text-decoration:none}}
a:hover{{text-decoration:underline}}
summary{{cursor:pointer;color:#93c5fd}}
</style></head><body>
<h1>Resumen v2.6 (SSH + ICMP/DNS/HTTP)</h1>
<small>Generado: {now} | Ventana: {RUN_DURATION_S}s | P_ICMP={P_ICMP} P_DNS={P_DNS} P_HTTP={P_HTTP} | Carpeta: logs/</small>
<table>
  <thead>
    <tr>
      <th>Session</th><th>Host</th><th>IP</th><th>Status</th><th>Duración (s)</th>
      <th>Errores</th><th>Precheck</th><th>Banner</th><th>Artefactos</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows)}
  </tbody>
</table>
</body></html>"""
    with html_path.open("w", encoding="utf-8") as f:
        f.write(doc)
    return {"csv": str(csv_path), "html": str(html_path)}

def main():
    inv = load_inventory(INVENTORY_FILE)
    hosts = inv["hosts"]
    max_workers = min(8, len(hosts)) or 1

    print(
        f"Inventario: {len(hosts)} hosts | Ventana: {RUN_DURATION_S}s | "
        f"Idle: {SESSION_IDLE_RANGE}s | Cmds/sesión: {SESSION_CMDS_RANGE} | "
        f"OUT-SSH: ICMP={P_ICMP} DNS={P_DNS} HTTP={P_HTTP} | Logs -> {LOG_DIR}/"
    )

    stop_time = time.time() + RUN_DURATION_S
    all_results = []

    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        for idx, h in enumerate(hosts):
            futures.append(ex.submit(run_host_sessions, h, stop_time, idx))

        for fut in cf.as_completed(futures):
            host_results = fut.result()
            all_results.extend(host_results)
            if host_results:
                last = host_results[-1]
                status = "OK" if last["ok"] and not last["errors"] else ("WARN" if last["ok"] else "FAIL")
                print(f"[{status}] {last['host']} last_session={last.get('session_id','')} dur={last['duration_s']}s errs={len(last['errors'])}")

    paths = write_reports(all_results)
    print(f"Reportes: {paths['html']}  |  {paths['csv']}")
    print(f"Total sesiones: {len(all_results)}")

if __name__ == "__main__":
    main()
