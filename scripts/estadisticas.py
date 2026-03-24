# ======================== USO DEL SCRIPT ========================
# Ejecución básica:
#   python pcap_stats.py captura.pcap
#
# Mostrar más elementos en las estadísticas (Top N):
#   python pcap_stats.py captura.pcap --top 20
#
# Generar resumen en formato JSON:
#   python pcap_stats.py captura.pcap --json resumen.json
#
# Generar gráficos (PNG) de las estadísticas:
#   python pcap_stats.py captura.pcap --plots
#
# Especificar directorio de salida de los gráficos:
#   python pcap_stats.py captura.pcap --plots --outdir graficas_resultados
#
# Ejecutar en servidores sin entorno gráfico (solo guardar gráficas):
#   python pcap_stats.py captura.pcap --plots --no-show
#
# Ejecución completa (JSON + gráficas + Top personalizado):
#   python pcap_stats.py captura.pcap --top 15 --json resultados.json --plots --outdir salidas_graficas --no-show
#
# python pcap_stats_tfm.py captura.pcapng --plots --no-show --json resumen.json --bucket 1
#
#  ================================================================

import argparse
import json
import os
import math
from dataclasses import dataclass
from collections import Counter
from datetime import datetime
from typing import Optional


import ipaddress
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scapy.all import (
    RawPcapReader, Ether, IP, IPv6, TCP, UDP, DNS,
    ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, Raw
)

# ======================== Utilidades ========================

def human_bytes(n: float) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"


def percentile(data, p: float) -> float:
    """Percentil lineal (tipo numpy) sin dependencias externas.

    - data: lista de números
    - p: percentil en [0, 100]
    """
    if not data:
        return 0.0
    if p <= 0:
        return float(min(data))
    if p >= 100:
        return float(max(data))
    xs = sorted(float(x) for x in data)
    k = (len(xs) - 1) * (p / 100.0)
    f = int(math.floor(k))
    c = int(math.ceil(k))
    if f == c:
        return xs[f]
    d0 = xs[f] * (c - k)
    d1 = xs[c] * (k - f)
    return d0 + d1


def ts_seconds(md) -> float:
    """
    Timestamp robusto para PCAP/PCAPNG (RawPcapReader).
    Intenta múltiples layouts porque scapy puede variar según versión/formato.

    Retorna 0.0 si no logra extraer un timestamp válido.
    """
    sec = getattr(md, "sec", None)
    usec = getattr(md, "usec", None)

    if sec is not None and usec is not None:
        # pcap clásico: sec + usec
        try:
            return float(sec) + float(usec) / 1e6
        except Exception:
            return 0.0

    # pcapng: a veces (tshigh, tslow, tsresol)
    tshigh = getattr(md, "tshigh", None)
    tslow = getattr(md, "tslow", None)
    tsresol = getattr(md, "tsresol", None)
    if tshigh is not None and tslow is not None:
        try:
            ts64 = (int(tshigh) << 32) | int(tslow)
            if tsresol is None:
                return float(ts64) / 1e6
            return float(ts64) / float(tsresol)
        except Exception:
            return 0.0

    return 0.0


def proto_name(ipver: Optional[str], proto_num: Optional[int]) -> str:
    if ipver == 'IPv4':
        mapping = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return mapping.get(proto_num, f"IPv4_{proto_num}")
    if ipver == 'IPv6':
        mapping = {58: 'ICMPv6', 6: 'TCP', 17: 'UDP'}
        return mapping.get(proto_num, f"IPv6_{proto_num}")
    return "UNKNOWN"


def entropy_from_counter(c: Counter) -> float:
    total = sum(c.values())
    if total <= 0:
        return 0.0
    ent = 0.0
    for v in c.values():
        p = v / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def burstiness_index(iats: list) -> float:
    # Índice simple: (std - mean)/(std + mean) (usa solo iats > 0)
    vals = [x for x in iats if x and x > 0]
    if len(vals) < 2:
        return 0.0
    mean = sum(vals) / len(vals)
    var = sum((x - mean) ** 2 for x in vals) / (len(vals) - 1)
    std = math.sqrt(var)
    denom = (std + mean)
    return (std - mean) / denom if denom > 0 else 0.0


def autocorr_lag1(series: list) -> float:
    # autocorr simple lag-1
    if not series or len(series) < 3:
        return 0.0
    x = series
    mean = sum(x) / len(x)
    num = 0.0
    den = 0.0
    for i in range(1, len(x)):
        num += (x[i] - mean) * (x[i - 1] - mean)
    for i in range(len(x)):
        den += (x[i] - mean) ** 2
    return (num / den) if den > 0 else 0.0


def windowed_counts(times: list, t0: float, win_s: int) -> dict:
    """
    Cuenta eventos por ventana fija win_s (segundos).
    times: lista timestamps absolutos (segundos)
    Retorna dict {k: count} donde k es índice de ventana desde t0.
    """
    c = Counter()
    for t in times:
        if t <= 0:
            continue
        k = int((t - t0) // win_s)
        if k >= 0:
            c[k] += 1
    return dict(c)


def is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except Exception:
        return False


# ======================== Heurísticas App-Proto ========================

def heuristic_app_proto(tcp_dport: Optional[int], udp_dport: Optional[int], tcp_sport: Optional[int], udp_sport: Optional[int],
                        payload: bytes) -> str:
    # Heurística muy ligera: puertos comunes y algo de parsing superficial
    ports = [p for p in [tcp_dport, udp_dport, tcp_sport, udp_sport] if p is not None]
    ports_set = set(ports)

    if 443 in ports_set:
        # Puede ser HTTPS o QUIC
        # Si UDP 443, asumimos QUIC (muy a menudo)
        if udp_dport == 443 or udp_sport == 443:
            return "QUIC/HTTP3"
        return "HTTPS"
    if 80 in ports_set:
        return "HTTP"
    if 53 in ports_set:
        return "DNS"
    if 123 in ports_set:
        return "NTP"
    if 22 in ports_set:
        return "SSH"
    if 25 in ports_set or 587 in ports_set:
        return "SMTP"
    if 110 in ports_set or 995 in ports_set:
        return "POP3"
    if 143 in ports_set or 993 in ports_set:
        return "IMAP"
    if 3389 in ports_set:
        return "RDP"

    # Quick check HTTP method
    if payload:
        pl = payload[:8]
        if pl.startswith(b"GET ") or pl.startswith(b"POST") or pl.startswith(b"HEAD") or pl.startswith(b"PUT "):
            return "HTTP"
    return "UNKNOWN"


def try_parse_http(payload: bytes):
    # Devuelve (method, host) si detecta algo
    if not payload:
        return None, None
    try:
        txt = payload.decode("utf-8", errors="ignore")
    except Exception:
        return None, None
    lines = txt.split("\r\n")
    if not lines:
        return None, None
    first = lines[0].strip()
    method = None
    if first.startswith(("GET ", "POST", "HEAD", "PUT ", "DELETE", "OPTIONS")):
        method = first.split()[0]
    host = None
    for ln in lines[1:25]:
        if ln.lower().startswith("host:"):
            host = ln.split(":", 1)[1].strip()
            break
    return method, host


# QUIC heurística muy simplificada
def try_parse_quic(payload: bytes) -> Optional[str]:
    # Detecta long header QUIC (primer byte con bits específicos) y devuelve "v1?" o "unknown"
    # (no es parser completo)
    if not payload or len(payload) < 6:
        return None
    b0 = payload[0]
    # QUIC long header: bit más alto =1 y fixed bit=1 (aprox), aquí super simplificado
    if (b0 & 0x80) and (b0 & 0x40):
        return "LONG_HDR"
    return None


# ======================== Plot helpers ========================

def ensure_outdir(path: str):
    os.makedirs(path, exist_ok=True)


def plot_time_series(x, y, title, xlabel, ylabel, outpath, show=False):
    plt.figure()
    plt.plot(x, y)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    if show:
        plt.show()
    plt.close()


def plot_hist(data, title, xlabel, outpath, bins=50, logx=False, logy=False, show=False):
    plt.figure()
    plt.hist(data, bins=bins)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel("count")
    if logx:
        plt.xscale("log")
    if logy:
        plt.yscale("log")
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    if show:
        plt.show()
    plt.close()


def plot_bar(counter_items, title, xlabel, ylabel, outpath, top=20, show=False):
    items = counter_items[:top]
    labels = [str(k) for k, _ in items]
    vals = [v for _, v in items]
    plt.figure(figsize=(10, max(3, len(labels) * 0.25)))
    plt.barh(labels[::-1], vals[::-1])
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    if show:
        plt.show()
    plt.close()


def ecdf(data):
    xs = sorted(data)
    n = len(xs)
    ys = [(i + 1) / n for i in range(n)]
    return xs, ys


def plot_ecdf(data, title, xlabel, outpath, show=False, logx=False):
    if not data:
        return
    xs, ys = ecdf(data)
    plt.figure()
    plt.plot(xs, ys)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel("CDF")
    if logx:
        plt.xscale("log")
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    if show:
        plt.show()
    plt.close()


def plot_ccdf(data, title, xlabel, outpath, show=False, logx=False):
    if not data:
        return
    xs = sorted(data)
    n = len(xs)
    ys = [1 - (i + 1) / n for i in range(n)]
    plt.figure()
    plt.plot(xs, ys)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel("CCDF")
    if logx:
        plt.xscale("log")
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    if show:
        plt.show()
    plt.close()


# ======================== Flows ========================

@dataclass(frozen=True)
class FlowKey:
    ipver: str
    src: str
    dst: str
    sport: int
    dport: int
    proto: str  # "TCP"/"UDP"/...


@dataclass
class FlowStats:
    start_ts: float = 0.0
    end_ts: float = 0.0
    bytes: int = 0
    packets: int = 0


# ======================== Main ========================

def main():
    parser = argparse.ArgumentParser(description="PCAP analyzer (TFM metrics + plots)")
    parser.add_argument("--pcap", required=True, help="Ruta al fichero .pcap/.pcapng")
    parser.add_argument("--outdir", default="out", help="Directorio de salida para gráficos")
    parser.add_argument("--top", type=int, default=15, help="Top-N para listas")
    parser.add_argument("--bucket", type=int, default=1, help="Bucket (segundos) para serie temporal throughput")
    parser.add_argument("--show", action="store_true", help="Mostrar plots (si entorno lo soporta)")
    parser.add_argument("--json_out", default="", help="Ruta para guardar métricas en JSON (opcional)")
    parser.add_argument("--local_ip", default="", help="IP local del host cliente para contar tráfico saliente (ej: 192.168.1.123). Si se omite, se intenta inferir automáticamente.")
    args = parser.parse_args()

    # IP local para contadores 'outbound' (host -> red)
    local_ip = args.local_ip.strip() if args.local_ip else ""
    local_ip_source = "arg" if local_ip else ""

    ensure_outdir(args.outdir)
    show_plots = args.show

    # Contadores / métricas globales
    total_pkts = 0
    total_bytes = 0
    sizes = []

    eth_types = Counter()
    ip_versions = Counter()
    ip_proto = Counter()

    app_proto = Counter()
    http_methods = Counter()
    http_hosts = Counter()
    quic_versions = Counter()

    src_ips = Counter()
    dst_ips = Counter()
    pairs = Counter()

    tcp_src_ports = Counter()
    tcp_dst_ports = Counter()
    udp_src_ports = Counter()
    udp_dst_ports = Counter()
    # Contadores de puertos destino SOLO en tráfico saliente (host -> red)
    tcp_dport_out = Counter()
    udp_dport_out = Counter()
    tcp_flag_counts = Counter()

    dns_queries = Counter()
    icmp_counts = Counter()

    packet_ts = []
    packet_len = []

    bad_frames = 0
    zero_ts = 0
    min_ts_nonzero = None
    max_ts_nonzero = None

    # Flujos unidireccionales
    flows = {}  # FlowKey -> FlowStats
    flow_stats = {}  # FlowKey -> FlowStats (alias)

    # Para nuevos flujos/iat
    new_flow_ts = []

    # Leer PCAP
    for pkt_data, md in RawPcapReader(args.pcap):
        total_pkts += 1
        ts = ts_seconds(md)

        if ts <= 0:
            zero_ts += 1
        else:
            if min_ts_nonzero is None or ts < min_ts_nonzero:
                min_ts_nonzero = ts
            if max_ts_nonzero is None or ts > max_ts_nonzero:
                max_ts_nonzero = ts

        packet_ts.append(ts)
        plen = len(pkt_data)
        packet_len.append(plen)
        sizes.append(plen)
        total_bytes += plen

        try:
            eth = Ether(pkt_data)
        except Exception:
            bad_frames += 1
            continue

        eth_types[str(eth.type)] += 1

        ipver = None
        src = None
        dst = None
        proto_num = None

        tcp = None
        udp = None
        payload = b""

        if eth.haslayer(IP):
            ip = eth[IP]
            ipver = "IPv4"
            src = ip.src
            dst = ip.dst
            proto_num = ip.proto
            ip_versions[ipver] += 1
        elif eth.haslayer(IPv6):
            ip6 = eth[IPv6]
            ipver = "IPv6"
            src = ip6.src
            dst = ip6.dst
            proto_num = ip6.nh
            ip_versions[ipver] += 1

        proto = proto_name(ipver, proto_num)
        ip_proto[proto] += 1

        
    if ipver and src and dst:
        src_ips[src] += 1
        dst_ips[dst] += 1
        pairs[(src, dst)] += 1

        # Inferencia ligera de IP local si no se proporcionó (elige la IP privada más frecuente como src)
        if not local_ip and is_private_ip(src) and total_pkts >= 200:
            private_src = [(ip, c) for ip, c in src_ips.items() if is_private_ip(ip)]
            if private_src:
                local_ip = max(private_src, key=lambda x: x[1])[0]
                local_ip_source = "inferred"

            # L4
            sport = None
            dport = None
            if eth.haslayer(TCP):
                tcp = eth[TCP]
                sport = int(tcp.sport)
                dport = int(tcp.dport)
                tcp_src_ports[sport] += 1
                tcp_dst_ports[dport] += 1

                # Contar puertos destino del servicio SOLO en tráfico saliente (host -> red)
                if local_ip and src == local_ip and dport is not None:
                    tcp_dport_out[dport] += 1
                tcp_flag_counts[str(tcp.flags)] += 1
                payload = bytes(tcp.payload) if tcp.payload else b""
            elif eth.haslayer(UDP):
                udp = eth[UDP]
                sport = int(udp.sport)
                dport = int(udp.dport)
                udp_src_ports[sport] += 1
                udp_dst_ports[dport] += 1

                # Contar puertos destino del servicio SOLO en tráfico saliente (host -> red)
                if local_ip and src == local_ip and dport is not None:
                    udp_dport_out[dport] += 1
                payload = bytes(udp.payload) if udp.payload else b""
            elif eth.haslayer(ICMP):
                ic = eth[ICMP]
                icmp_counts[str(ic.type)] += 1
            elif eth.haslayer(ICMPv6EchoRequest) or eth.haslayer(ICMPv6EchoReply):
                icmp_counts["ICMPv6"] += 1

            # DNS
            if eth.haslayer(DNS):
                dns = eth[DNS]
                # Query?
                if getattr(dns, "qr", 1) == 0 and getattr(dns, "qdcount", 0) > 0:
                    try:
                        qname = dns.qd.qname.decode("utf-8", errors="ignore").strip(".")
                        dns_queries[qname] += 1
                    except Exception:
                        pass

            # Heurísticas app
            ap = heuristic_app_proto(
                tcp_dport=dport if tcp else None,
                udp_dport=dport if udp else None,
                tcp_sport=sport if tcp else None,
                udp_sport=sport if udp else None,
                payload=payload
            )
            app_proto[ap] += 1

            # HTTP
            if ap.startswith("HTTP") and payload:
                m, h = try_parse_http(payload)
                if m:
                    http_methods[m] += 1
                if h:
                    http_hosts[h] += 1

            # QUIC
            if ap.startswith("QUIC") and payload:
                q = try_parse_quic(payload)
                if q:
                    quic_versions[q] += 1

            # Flujos: solo si tenemos ip+L4
            if ipver and src and dst and sport is not None and dport is not None and proto in ("TCP", "UDP"):
                fk = FlowKey(ipver=ipver, src=src, dst=dst, sport=sport, dport=dport, proto=proto)
                if fk not in flows:
                    flows[fk] = FlowStats(start_ts=ts, end_ts=ts, bytes=plen, packets=1)
                    new_flow_ts.append(ts)
                else:
                    fs = flows[fk]
                    if fs.start_ts == 0.0:
                        fs.start_ts = ts
                    fs.end_ts = ts if ts > 0 else fs.end_ts
                    fs.bytes += plen
                    fs.packets += 1
                    


    # Alias
    flow_stats = flows

    # Duración
    duration_bucket = 0.0
    duration_ts = 0.0

    # Usar timestamps no-cero si fiables
    ts_zero_ratio = (zero_ts / total_pkts) if total_pkts > 0 else 1.0

    if min_ts_nonzero is not None and max_ts_nonzero is not None and max_ts_nonzero >= min_ts_nonzero:
        duration_ts = max_ts_nonzero - min_ts_nonzero
    else:
        duration_ts = 0.0

    # duration_bucket basado en buckets construidos por timestamps (si hay timestamps 0, puede fallar)
    duration_bucket = duration_ts

    # Si demasiados timestamps=0, preferimos duration por bucket colapsado si hay alternativa
    duration_reason = "duration_ts"
    duration = duration_ts

    if duration_ts <= 0 and packet_ts:
        # fallback: usar índice de paquetes como pseudo-tiempo (NO ideal)
        duration_bucket = len(packet_ts) * 0.0
        duration = duration_bucket
        duration_reason = "fallback_invalid_ts"
    else:
        # Si bucket puede ser estimado, mantenlo
        duration_bucket = duration_ts
        if duration_bucket > 0 and (duration_bucket < duration_ts or duration_ts == 0):
            duration = duration_ts
            duration_reason = "bucket_colapsado->duration_ts"
        else:
            duration = duration_bucket if duration_bucket > 0 else duration_ts
            duration_reason = "duration_bucket" if duration_bucket > 0 else "duration_ts"

    bps_avg = (total_bytes * 8 / duration) if duration and duration > 0 else 0.0

    # Serie temporal base (bps por bucket args.bucket) para autocorr y plots
    series_times = []
    series_mbps = []
    series_ok = (ts_zero_ratio <= 0.5)

    bytes_series = []
    bps_series = []

    if series_ok and min_ts_nonzero is not None and max_ts_nonzero is not None and duration_ts > 0:
        # bins por bucket desde min_ts_nonzero
        min_b = int(min_ts_nonzero // args.bucket)
        max_b = int(max_ts_nonzero // args.bucket)
        bytes_per_bucket = Counter()
        # reconstruir bytes por bucket a partir de paquetes (coste O(n))
        for t, l in zip(packet_ts, packet_len):
            if t <= 0:
                continue
            b = int(t // args.bucket)
            bytes_per_bucket[b] += l

        for b in range(min_b, max_b + 1):
            bytes_in_bucket = bytes_per_bucket.get(b, 0)
            mbps = (bytes_in_bucket * 8) / (args.bucket * 1e6)
            t = (b - min_b) * args.bucket
            series_times.append(t)
            series_mbps.append(mbps)

            bytes_series.append(bytes_in_bucket)
            bps_series.append((bytes_in_bucket * 8) / args.bucket)

    # ======================== Métricas TFM (A-D) ========================

    WINDOWS = [300, 900, 3600]  # 5m, 15m, 1h en segundos
    t0 = min_ts_nonzero if (min_ts_nonzero and min_ts_nonzero > 0) else (packet_ts[0] if packet_ts else 0.0)

    # A) Throughput medio por ventana 5/15/60 (bps) y nuevos flujos/min por ventana
    win_throughput_bps = {}     # win_s -> list[bps]
    win_newflows_per_min = {}   # win_s -> list[flows/min]

    if t0 and t0 > 0 and series_ok and bytes_series:
        for win_s in WINDOWS:
            buckets_per_win = max(1, int(round(win_s / args.bucket)))
            vals = []
            for i in range(0, len(bytes_series), buckets_per_win):
                chunk_bytes = sum(bytes_series[i:i + buckets_per_win])
                vals.append((chunk_bytes * 8) / win_s)
            win_throughput_bps[win_s] = vals

    if t0 and t0 > 0 and new_flow_ts:
        for win_s in WINDOWS:
            c = windowed_counts(new_flow_ts, t0, win_s)
            max_k = max(c.keys()) if c else -1
            series_nf = [c.get(i, 0) for i in range(max_k + 1)]
            win_newflows_per_min[win_s] = [x / (win_s / 60.0) for x in series_nf]

    # B) Estructura de sesiones: duración, bytes/flujo, pkts/flujo
    flow_durations = []
    flow_bytes = []
    flow_pkts = []
    for fs in flow_stats.values():
        if fs.start_ts and fs.end_ts and fs.end_ts >= fs.start_ts:
            flow_durations.append(fs.end_ts - fs.start_ts)
        else:
            flow_durations.append(0.0)
        flow_bytes.append(fs.bytes)
        flow_pkts.append(fs.packets)


    

    # Medianas (B) para tabla de estructura de flujos
    import statistics
    median_bytes_flow = statistics.median(flow_bytes) if flow_bytes else 0
    median_dur_flow   = statistics.median(flow_durations) if flow_durations else 0
    median_pkts_flow  = statistics.median(flow_pkts) if flow_pkts else 0

    print(f"Mediana bytes/flujo: {median_bytes_flow:.0f}")
    print(f"Mediana duración/flujo (s): {median_dur_flow:.3f}")
    print(f"Mediana pkts/flujo: {median_pkts_flow:.0f}")


    # C) Diversidad: destinos y DNS
    unique_dst_ips = len(dst_ips)
    entropy_dst_ips = entropy_from_counter(dst_ips)

    # dominios DNS: normalizar a dominio base simple
    dns_domains = Counter()
    for q, n in dns_queries.items():
        parts = q.split(".")
        if len(parts) >= 2:
            base = ".".join(parts[-2:])
        else:
            base = q
        dns_domains[base] += n
    unique_domains = len(dns_domains)
    entropy_domains = entropy_from_counter(dns_domains)

    # D) Temporalidad: IAT paquetes y IAT nuevos flujos
    pkt_iat = []
    if len(packet_ts) >= 2:
        ts_sorted = sorted([t for t in packet_ts if t and t > 0])
        pkt_iat = [ts_sorted[i] - ts_sorted[i - 1] for i in range(1, len(ts_sorted)) if ts_sorted[i] >= ts_sorted[i - 1]]

    flow_iat = []
    if len(new_flow_ts) >= 2:
        nfs = sorted(new_flow_ts)
        flow_iat = [nfs[i] - nfs[i - 1] for i in range(1, len(nfs)) if nfs[i] >= nfs[i - 1]]

    burst_pkt_iat = burstiness_index(pkt_iat)
    burst_flow_iat = burstiness_index(flow_iat)

    ac_throughput_lag1 = autocorr_lag1(bps_series) if bps_series else 0.0

    # Throughput pico/percentiles (bucket y ventanas)
    bucket_throughput_peak_mbps = None
    bucket_throughput_p95_mbps = None
    bucket_throughput_p99_mbps = None
    if series_ok and series_mbps:
        bucket_throughput_peak_mbps = max(series_mbps)
        bucket_throughput_p95_mbps = percentile(series_mbps, 95)
        bucket_throughput_p99_mbps = percentile(series_mbps, 99)

    windowed_throughput_summary_mbps = {}
    if win_throughput_bps:
        for win_s, vals in win_throughput_bps.items():
            if not vals:
                continue
            vals_mbps = [v / 1e6 for v in vals]
            windowed_throughput_summary_mbps[str(win_s)] = {
                "mean": (sum(vals_mbps) / len(vals_mbps)) if vals_mbps else 0.0,
                "p95": percentile(vals_mbps, 95) if vals_mbps else 0.0,
                "p99": percentile(vals_mbps, 99) if vals_mbps else 0.0,
                "max": max(vals_mbps) if vals_mbps else 0.0,
            }


    # ======================== Salida ========================

    # Fechas inicio/fin si existen
    try:
        start_dt = datetime.fromtimestamp(min_ts_nonzero) if min_ts_nonzero else None
        end_dt = datetime.fromtimestamp(max_ts_nonzero) if max_ts_nonzero else None
    except Exception:
        start_dt = end_dt = None

    if start_dt and end_dt:
        print(f"Inicio captura (ts no-cero): {start_dt} | Fin: {end_dt} | Duración usada: {duration:.3f} s ({duration_reason})")
    else:
        print(f"Duración usada (s): {duration:.3f} ({duration_reason})")

    if sizes:
        avg_sz = sum(sizes) / len(sizes)
        print(f"Paquetes: {total_pkts:,} | Tamaño total: {human_bytes(total_bytes)} | Media pqt: {avg_sz:.1f} B")
    else:
        print(f"Paquetes: {total_pkts:,} | Tamaño total: {human_bytes(total_bytes)}")

    if duration and duration > 0:
        print(f"Throughput promedio: {bps_avg/1e6:.3f} Mbps  (bucket={args.bucket}s)")

        # Throughput pico y percentiles (sobre la serie por buckets)
        if bucket_throughput_peak_mbps is not None:
            print(
                f"Throughput p95 (bucket={args.bucket}s): {bucket_throughput_p95_mbps:.3f} Mbps | "
                f"p99: {bucket_throughput_p99_mbps:.3f} Mbps | pico: {bucket_throughput_peak_mbps:.3f} Mbps"
            )

        # Resumen throughput por ventanas 5/15/60 (mean/p95/p99/max)
        if windowed_throughput_summary_mbps:
            for win_s in sorted(windowed_throughput_summary_mbps.keys(), key=lambda x: int(x)):
                s = windowed_throughput_summary_mbps[win_s]
                print(
                    f"Throughput ventana {int(int(win_s)/60)} min: mean={s['mean']:.3f} Mbps | "
                    f"p95={s['p95']:.3f} Mbps | p99={s['p99']:.3f} Mbps | max={s['max']:.3f} Mbps"
                )

    else:
        print("Throughput promedio: N/A (duración inválida; timestamps insuficientes)")

    print()
    print(f"Paquetes no parseados: {bad_frames}")

    print(f"Timestamps=0: {zero_ts:,} ({ts_zero_ratio*100:.1f}%)...nonzero_min={min_ts_nonzero} | ts_nonzero_max={max_ts_nonzero}")
    print()

    # Flujos
    flows_total = len(flows)
    if duration and duration > 0:
        duration_minutes = duration / 60.0
        flows_per_min = flows_total / duration_minutes if duration_minutes > 0 else 0.0
    else:
        flows_per_min = 0.0

    print(f"Flujos totales (unidireccionales): {flows_total:,}")
    print(f"Flujos por minuto (aprox): {flows_per_min:.2f}")
    print(f"Dst IP únicas: {unique_dst_ips:,} | Entropía dst IP: {entropy_dst_ips:.3f}")
    print(f"Dominios DNS únicos(base): {unique_domains:,} | Entropía dominios: {entropy_domains:.3f}")
    print(f"Burstiness pkt IAT: {burst_pkt_iat:.3f} | Burstiness new-flow IAT: {burst_flow_iat:.3f}")
    print(f"Autocorr lag-1 throughput (bps series): {ac_throughput_lag1:.3f}")
    print()

    # Tops rápidos (consola)
    print("Protocolos IP Top:")
    for k, v in ip_proto.most_common(args.top):
        print(f"  {k}: {v}")
    print()

    print("App-proto heurístico Top:")
    for k, v in app_proto.most_common(args.top):
        print(f"  {k}: {v}")
    print()

# Resumen de puertos salientes (host -> red) para servicios típicos
if local_ip:
    print(f"[INFO] IP local usada para outbound: {local_ip} ({local_ip_source})")
    print("Outbound (host->red) puertos destino (Top):")
    for k, v in tcp_dport_out.most_common(min(args.top, 10)):
        print(f"  TCP dport {k}: {v} pkts")
    for k, v in udp_dport_out.most_common(min(args.top, 10)):
        print(f"  UDP dport {k}: {v} pkts")
    print(f"TCP outbound dport=443: {tcp_dport_out.get(443,0)} pkts")
    print(f"UDP outbound dport=443: {udp_dport_out.get(443,0)} pkts")
    print(f"UDP outbound dport=53 (DNS): {udp_dport_out.get(53,0)} pkts")
    print()
else:
    print("[INFO] No se ha podido determinar IP local para outbound. Usa --local_ip para contar servicios (443/53) correctamente.")
    print()


    if http_hosts:
        print("HTTP Hosts detectados (Top):")
        for k, v in http_hosts.most_common(args.top):
            print(f"  {k}: {v}")
        print()

    if dns_queries:
        print("Consultas DNS (Top):")
        for k, v in dns_queries.most_common(args.top):
            print(f"  {k}: {v}")
        print()

    # ======================== JSON salida (opcional) ========================
    if args.json_out:
        out = {
            "packets": total_pkts,
            "bytes": total_bytes,
            "avg_packet_size": (sum(sizes) / len(sizes)) if sizes else 0,
            "bucket_seconds": args.bucket,

            "duration_bucket_seconds": duration_bucket,
            "duration_ts_seconds": duration_ts,
            "duration_used_seconds": duration,
            "duration_reason": duration_reason,

            "throughput_avg_bps": bps_avg,

            # Throughput pico/percentiles (bucket) y resumen por ventanas
            "throughput_peak_mbps_bucket": bucket_throughput_peak_mbps if bucket_throughput_peak_mbps is not None else None,
            "throughput_p95_mbps_bucket": bucket_throughput_p95_mbps if bucket_throughput_p95_mbps is not None else None,
            "throughput_p99_mbps_bucket": bucket_throughput_p99_mbps if bucket_throughput_p99_mbps is not None else None,
            "windowed_throughput_summary_mbps": windowed_throughput_summary_mbps,

            "timestamps_zero": zero_ts,
            "timestamps_zero_ratio": ts_zero_ratio,
            "ts_nonzero_min": min_ts_nonzero,
            "ts_nonzero_max": max_ts_nonzero,

            # TFM: flujos
            "flows_total": flows_total,
            "flows_per_min": flows_per_min,

            # TFM: diversidad
            "unique_dst_ips": unique_dst_ips,
            "entropy_dst_ips": entropy_dst_ips,
            "unique_dns_domains": unique_domains,
            "entropy_dns_domains": entropy_domains,

            # TFM: temporalidad
            "burstiness_pkt_iat": burst_pkt_iat,
            "burstiness_newflow_iat": burst_flow_iat,
            "autocorr_lag1_throughput_bps": ac_throughput_lag1,

            # Top lists
            "eth_types": eth_types.most_common(args.top),
            "ip_versions": ip_versions.most_common(args.top),
            "ip_protocols": ip_proto.most_common(args.top),

            "app_protocols_heuristic": app_proto.most_common(args.top),
            "http_methods_heuristic": http_methods.most_common(args.top),
            "http_hosts_heuristic": http_hosts.most_common(args.top),
            "quic_versions_heuristic": quic_versions.most_common(args.top),

            "top_src_ips": src_ips.most_common(args.top),
            "top_dst_ips": dst_ips.most_common(args.top),
            "top_ip_pairs": [(f"{a}->{b}", c) for (a, b), c in pairs.most_common(args.top)],
            "top_tcp_src_ports": tcp_src_ports.most_common(args.top),
            "top_tcp_dst_ports": tcp_dst_ports.most_common(args.top),
            "top_udp_src_ports": udp_src_ports.most_common(args.top),
            "top_udp_dst_ports": udp_dst_ports.most_common(args.top),

# Outbound (host->red): conteos útiles para "puertos de servicio"
"local_ip": local_ip if local_ip else None,
"local_ip_source": local_ip_source if local_ip_source else None,
"tcp_outbound_total_pkts": sum(tcp_dport_out.values()),
"udp_outbound_total_pkts": sum(udp_dport_out.values()),
"tcp_outbound_dport_443_pkts": tcp_dport_out.get(443, 0),
"udp_outbound_dport_443_pkts": udp_dport_out.get(443, 0),
"udp_outbound_dport_53_pkts": udp_dport_out.get(53, 0),
            "tcp_flags": tcp_flag_counts.most_common(args.top),
            "dns_queries": dns_queries.most_common(args.top),
            "icmp": icmp_counts.most_common(args.top),
            "bad_frames": bad_frames,

            # TFM: estructura de sesiones (distribuciones crudas)
            "flows_duration_seconds_list": flow_durations[:50000],  # evita JSON gigante
            "flows_bytes_list": flow_bytes[:50000],
            "flows_packets_list": flow_pkts[:50000],

            # TFM: inter-arrival (recortado)
            "packet_iat_seconds_list": pkt_iat[:50000],
            "newflow_iat_seconds_list": flow_iat[:50000],
            
            "median_bytes_per_flow": median_bytes_flow,
            "median_flow_duration_s": median_dur_flow,
            "median_pkts_per_flow": median_pkts_flow,

        }

        # Serie throughput base por bucket si fiable
        if series_ok:
            out["throughput_series"] = {
                "times_seconds_from_start": series_times,
                "mbps": series_mbps
            }
        else:
            out["throughput_series"] = "NOT_RELIABLE_TOO_MANY_ZERO_TIMESTAMPS"

        # Series por ventana 5/15/60
        if win_throughput_bps:
            out["windowed_throughput_bps"] = {str(k): v for k, v in win_throughput_bps.items()}
        if win_newflows_per_min:
            out["windowed_newflows_per_min"] = {str(k): v for k, v in win_newflows_per_min.items()}

        # Top flows (para inspección)
        out["top_flows_unidirectional"] = [
            {
                "ip_version": f[0],
                "src": f[1],
                "dst": f[2],
                "sport": f[3],
                "dport": f[4],
                "proto": f[5],
                "bytes": fs.bytes,
                "packets": fs.packets,
                "duration": (fs.end_ts - fs.start_ts) if fs.end_ts and fs.start_ts and fs.end_ts >= fs.start_ts else 0.0
            }
            for f, fs in sorted(
                (( (fk.ipver, fk.src, fk.dst, fk.sport, fk.dport, fk.proto), fs) for fk, fs in flow_stats.items()),
                key=lambda x: x[1].bytes,
                reverse=True
            )[:args.top]
        ]

        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"[OK] JSON guardado en: {args.json_out}")

    # ======================== Gráficas ========================

    # Graficar contadores principales
    plot_bar(eth_types.most_common(args.top), "Eth types (top)", "count", "eth.type", os.path.join(args.outdir, "eth_types.png"), top=args.top, show=show_plots)
    plot_bar(ip_versions.most_common(args.top), "IP versions (top)", "count", "ipver", os.path.join(args.outdir, "ip_versions.png"), top=args.top, show=show_plots)
    plot_bar(ip_proto.most_common(args.top), "IP protocols (top)", "count", "proto", os.path.join(args.outdir, "ip_protocols.png"), top=args.top, show=show_plots)

    plot_bar(app_proto.most_common(args.top), "App proto heuristic (top)", "count", "app", os.path.join(args.outdir, "app_protocols.png"), top=args.top, show=show_plots)

    # Puertos
    plot_bar(tcp_dst_ports.most_common(args.top), "TCP dst ports (top)", "count", "port", os.path.join(args.outdir, "tcp_dst_ports.png"), top=args.top, show=show_plots)
    plot_bar(udp_dst_ports.most_common(args.top), "UDP dst ports (top)", "count", "port", os.path.join(args.outdir, "udp_dst_ports.png"), top=args.top, show=show_plots)



# Puertos outbound (host->red) - más interpretables que dst_ports generales
if tcp_dport_out:
    plot_bar(tcp_dport_out.most_common(args.top), "TCP dports outbound (host->red)", "pkts", "dport",
             os.path.join(args.outdir, "tcp_outbound_dports.png"), top=args.top, show=show_plots)
if udp_dport_out:
    plot_bar(udp_dport_out.most_common(args.top), "UDP dports outbound (host->red)", "pkts", "dport",
             os.path.join(args.outdir, "udp_outbound_dports.png"), top=args.top, show=show_plots)

    # Top destinos
    plot_bar(dst_ips.most_common(args.top), "Top dst IPs", "count", "dst_ip", os.path.join(args.outdir, "top_dst_ips.png"), top=args.top, show=show_plots)

    # DNS y HTTP
    if dns_queries:
        plot_bar(dns_queries.most_common(args.top), "Top DNS queries", "count", "qname", os.path.join(args.outdir, "top_dns_queries.png"), top=args.top, show=show_plots)
    if http_hosts:
        plot_bar(http_hosts.most_common(args.top), "Top HTTP hosts (heuristic)", "count", "host", os.path.join(args.outdir, "top_http_hosts.png"), top=args.top, show=show_plots)

    # Serie throughput base (si fiable)
    if series_ok and series_times and series_mbps:
        plot_time_series(
            series_times,
            series_mbps,
            f"Throughput por bucket={args.bucket}s",
            "Segundos desde inicio",
            "Mbps",
            os.path.join(args.outdir, "throughput_por_bucket.png"),
            show_plots
        )
    else:
        print("WARNING: No se grafica throughput temporal base: demasiados timestamps=0 o timestamps no fiables.")

    # ======================== Gráficas TFM extra ========================

    # A) Throughput medio por ventanas 5/15/60
    for win_s, series in win_throughput_bps.items():
        if series:
            times = [i * (win_s / 60.0) for i in range(len(series))]  # minutos
            plot_time_series(
                times, [v / 1e6 for v in series],
                f"Throughput medio por ventana ({int(win_s/60)} min)",
                "Minutos desde inicio",
                "Mbps",
                os.path.join(args.outdir, f"throughput_window_{win_s}s.png"),
                show_plots
            )

    for win_s, series in win_newflows_per_min.items():
        if series:
            times = [i * (win_s / 60.0) for i in range(len(series))]
            plot_time_series(
                times, series,
                f"Nuevos flujos por minuto ({int(win_s/60)} min)",
                "Minutos desde inicio",
                "flujos/min",
                os.path.join(args.outdir, f"new_flows_per_min_window_{win_s}s.png"),
                show_plots
            )

    # B) CDF/CCDF bytes por flujo + duración (colas pesadas) + hist pkts/flujo
    plot_ecdf(flow_bytes, "CDF bytes por flujo", "Bytes por flujo",
              os.path.join(args.outdir, "cdf_bytes_per_flow.png"), show=show_plots, logx=True)
    plot_ccdf(flow_bytes, "CCDF bytes por flujo", "Bytes por flujo",
              os.path.join(args.outdir, "ccdf_bytes_per_flow.png"), show=show_plots, logx=True)

    plot_ecdf(flow_durations, "CDF duración de flujo", "Duración (s)",
              os.path.join(args.outdir, "cdf_flow_duration.png"), show=show_plots, logx=True)
    plot_ccdf(flow_durations, "CCDF duración de flujo", "Duración (s)",
              os.path.join(args.outdir, "ccdf_flow_duration.png"), show=show_plots, logx=True)

    plot_hist(flow_pkts, "Hist pkts por flujo", "pkts/flujo",
              os.path.join(args.outdir, "hist_pkts_per_flow.png"), bins=60, logx=True, logy=True, show=show_plots)
    
    

    # D) Temporalidad: IAT hist
    if pkt_iat:
        plot_hist(pkt_iat, "Hist IAT paquetes", "IAT (s)",
                  os.path.join(args.outdir, "hist_pkt_iat.png"), bins=80, logx=True, logy=True, show=show_plots)
    if flow_iat:
        plot_hist(flow_iat, "Hist IAT nuevos flujos", "IAT (s)",
                  os.path.join(args.outdir, "hist_newflow_iat.png"), bins=80, logx=True, logy=True, show=show_plots)

    print(f"[OK] Gráficas guardadas en: {args.outdir}")


if __name__ == "__main__":
    main()
