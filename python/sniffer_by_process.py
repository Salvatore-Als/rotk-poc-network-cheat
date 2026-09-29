"""
sniffer_by_process.py — Sniffer ROTK, filtrage par processus.

Identifie les ports UDP ouverts par H1Z1/ROTK via psutil et capture uniquement
ce trafic, quelle que soit l'IP distante. Les ports sont rafraîchis en continu
(login, gateway, zone s'ouvrent à des moments différents).

Prérequis : pip install scapy psutil
Windows   : PowerShell administrateur + Npcap installé
"""

import struct
import sys
import os
import time
import threading
import queue
from datetime import datetime
from collections import Counter

import psutil
from scapy.all import sniff, UDP, TCP, IP, Raw

from soe_reassembly import SOEInputStream, DEFAULT_CRYPTO_KEY, POSITION_BROADCAST_OPCODES

# ── Config ────────────────────────────────────────────────────────────────────
# Noms de fichiers psutil (pas les noms affichés par Task Manager).
# En dernier recours le script propose une sélection manuelle.
PROCESS_NAME_HINTS   = ["h1z1", "daybreak", "soe", "gamex"]
PROCESS_NAME_EXCLUDE = ["launcher"]

# Refresh serré pour capter le SessionRequest de la zone dès l'ouverture du socket.
REFRESH_SECS = 0.05

LOG_FILE           = "rotk-capture-byprocess.log"
PRINT_SCREEN       = True
MAX_PAYLOAD        = 2048
CRC_LENGTH         = 2
DECODED_DIR        = "decoded_packets"
POSITIONS_LOG_FILE = "rotk-player-positions.log"
# ─────────────────────────────────────────────────────────────────────────────

SOE_OPCODES = {
    0x0001: "SessionRequest",
    0x0002: "SessionReply",
    0x0003: "MultiPacket",
    0x0005: "Disconnect",
    0x0006: "Heartbeat",
    0x0007: "NetStatusRequest",
    0x0008: "NetStatusReply",
    0x0009: "Data",
    0x000D: "DataFragment",
    0x0015: "Ack",
    0x0019: "AckAll",
    0x001D: "OutOfOrder",
}

stats = {"total": 0, "tcp": 0, "udp": 0, "soe_recognized": 0, "bytes": 0}
log_handle = None
positions_log_handle = None

# Ports locaux surveillés — rafraîchis en continu par le thread de polling.
# Clé = numéro de port, valeur = "udp" ou "tcp".
watched_ports: dict[int, str] = {}
watched_ports_lock = threading.Lock()

# Tampon rétroactif : un nouveau port peut recevoir des paquets avant que le
# polling l'ait détecté. On garde les paquets non reconnus quelques secondes
# et on les rejoue dès que le port est enregistré.
BUFFER_RETENTION_SECS = 8
packet_buffer: list = []   # [(capture_dt, proto, src, sport, dst, dport, data)]
packet_buffer_lock = threading.Lock()
seen_remote_ips: set[str] = set()
stop_polling = threading.Event()

# Un SOEInputStream par port local, créé dès le SessionRequest sortant.
soe_channels: dict[int, SOEInputStream] = {}
soe_lock = threading.Lock()
position_count = 0

# Queue producer/consumer pour ne jamais bloquer le callback scapy.
_pkt_queue: queue.Queue = queue.Queue(maxsize=200_000)


# ── Sélection du processus ───────────────────────────────────────────────────

def get_file_description(exe_path: str) -> str:
    """Lit la FileDescription Win32 de l'exe — souvent différente du nom de fichier réel."""
    if not exe_path or sys.platform != "win32":
        return ""
    try:
        import ctypes
        from ctypes import wintypes

        size = ctypes.windll.version.GetFileVersionInfoSizeW(exe_path, None)
        if not size:
            return ""

        buf = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(exe_path, 0, size, buf):
            return ""

        lplpbuf = ctypes.c_void_p()
        puLen = wintypes.UINT()
        if not ctypes.windll.version.VerQueryValueW(
            buf, "\\VarFileInfo\\Translation", ctypes.byref(lplpbuf), ctypes.byref(puLen)
        ):
            return ""

        lang, codepage = ctypes.cast(lplpbuf, ctypes.POINTER(ctypes.c_uint16 * 2)).contents
        sub = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\FileDescription"

        if not ctypes.windll.version.VerQueryValueW(
            buf, sub, ctypes.byref(lplpbuf), ctypes.byref(puLen)
        ):
            return ""

        return ctypes.wstring_at(lplpbuf.value, puLen.value - 1) if puLen.value else ""
    except Exception:
        return ""


def find_candidate_processes() -> list[psutil.Process]:
    candidates = []
    for p in psutil.process_iter(["pid", "name", "exe"]):
        name = (p.info.get("name") or "").lower()
        if any(excl in name for excl in PROCESS_NAME_EXCLUDE):
            continue
        if any(hint in name for hint in PROCESS_NAME_HINTS):
            candidates.append(p)
    return candidates


def list_all_processes() -> list[psutil.Process]:
    procs = []
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            if p.info.get("exe"):
                procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return sorted(procs, key=lambda p: (p.info.get("name") or "").lower())


def pick_from_list(procs: list[psutil.Process]) -> psutil.Process:
    print()
    for i, p in enumerate(procs, 1):
        desc = get_file_description(p.info.get("exe", ""))
        desc_part = ""
        if desc:
            desc_part = f"  — {desc}"
        print(f"  {i:>4}. {p.info['name']:<30} PID={p.info['pid']:<8}{desc_part}")

    while True:
        choice = input("\nChoix (numéro, ou 'q' pour annuler) : ").strip().lower()
        if choice == "q":
            sys.exit(0)
        try:
            idx = int(choice)
            if 1 <= idx <= len(procs):
                return procs[idx - 1]
        except ValueError:
            pass
        print("  Entrée invalide.")


def choose_process() -> psutil.Process:
    print("[*] Recherche automatique du processus H1Z1/ROTK...")
    candidates = find_candidate_processes()

    if len(candidates) == 1:
        p = candidates[0]
        print(f"[*] Processus trouvé : {p.info['name']} (PID {p.info['pid']})")
        return p

    if len(candidates) > 1:
        print("\n[*] Plusieurs processus correspondent :\n")
        return pick_from_list(candidates)

    # Aucun match — on attend le lancement du jeu. Ctrl+C bascule en sélection manuelle.
    print("[!] Processus non trouvé — en attente du lancement du jeu...")
    print("    (Ctrl+C pour sélection manuelle)")
    try:
        attempt = 0
        while True:
            time.sleep(0.5)
            attempt += 1
            candidates = find_candidate_processes()
            if candidates:
                if len(candidates) == 1:
                    p = candidates[0]
                    print(f"\n[*] Processus détecté : {p.info['name']} (PID {p.info['pid']})")
                    return p
                print("\n[*] Plusieurs processus détectés :\n")
                return pick_from_list(candidates)
            if attempt % 10 == 0:
                print(f"[*] Toujours en attente... ({attempt // 2}s)")
    except KeyboardInterrupt:
        print("\n[*] Passage en sélection manuelle.")

    while True:
        print("\nOptions :")
        print("  1. Réessayer la recherche automatique")
        print("  2. Chercher par mot-clé")
        print("  3. Lister tous les processus")
        print("  4. Entrer un PID directement")
        choice = input("Choix : ").strip()

        if choice == "1":
            candidates = find_candidate_processes()
            if candidates:
                return candidates[0] if len(candidates) == 1 else pick_from_list(candidates)
            print("[!] Toujours rien trouvé.")

        elif choice == "2":
            kw = input("Mot-clé (insensible à la casse) : ").strip().lower()
            matches = [
                p for p in psutil.process_iter(["pid", "name", "exe"])
                if kw in (p.info.get("name") or "").lower()
            ]
            if matches:
                return matches[0] if len(matches) == 1 else pick_from_list(matches)
            print(f"[!] Aucun processus ne contient '{kw}'.")

        elif choice == "3":
            return pick_from_list(list_all_processes())

        elif choice == "4":
            try:
                pid = int(input("PID : ").strip())
                return psutil.Process(pid)
            except (ValueError, psutil.NoSuchProcess):
                print("[!] PID invalide.")

        else:
            print("  Entrée invalide.")


# ── Rafraîchissement continu des ports locaux du process ────────────────────

def poll_ports(pid: int):
    """Rafraîchit les ports UDP/TCP du process en continu."""
    global watched_ports
    while not stop_polling.is_set():
        try:
            proc = psutil.Process(pid)
            new_ports: dict[int, str] = {}

            for c in proc.net_connections(kind="udp"):
                if c.laddr:
                    new_ports[c.laddr.port] = "udp"
            for c in proc.net_connections(kind="tcp"):
                if c.laddr:
                    new_ports[c.laddr.port] = "tcp"

            with watched_ports_lock:
                added = set(new_ports) - set(watched_ports)
                watched_ports.update(new_ports)

            if added:
                write(f"[*] Nouveaux ports locaux détectés : {sorted(added)}")
                replay_buffer_for_new_ports(added)

        except psutil.NoSuchProcess:
            write("[!] Le processus surveillé s'est terminé.")
            return

        stop_polling.wait(REFRESH_SECS)


# ── Log ───────────────────────────────────────────────────────────────────────

def open_log():
    global log_handle
    log_handle = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
    write(f"\n{'='*70}")
    write(f"Session : {datetime.now().isoformat()}")
    write(f"{'='*70}\n")


def write(line: str):
    if log_handle:
        log_handle.write(line + "\n")
    if PRINT_SCREEN:
        print(line)


# ── Parsing ───────────────────────────────────────────────────────────────────

def safe_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def parse_soe(data: bytes):
    if len(data) < 2:
        return "", None, 0

    opcode     = struct.unpack(">H", data[:2])[0]
    name       = SOE_OPCODES.get(opcode, f"UNKNOWN(0x{opcode:04x})")
    header_len = 2
    seq        = ""

    if len(data) >= 4 and opcode in (0x0009, 0x000D, 0x0015, 0x0019, 0x001D):
        seq        = f" seq={struct.unpack('>H', data[2:4])[0]}"
        header_len = 4

    return f"SOE:{name}{seq}", opcode, header_len


def format_packet(proto, direction, src, sport, dst, dport, data, cap_dt=None):
    ts            = (cap_dt or datetime.now()).strftime("%H:%M:%S.%f")[:-3]
    payload_hex   = data[:MAX_PAYLOAD].hex()
    payload_ascii = safe_ascii(data[:MAX_PAYLOAD])
    truncated     = f"…+{len(data) - MAX_PAYLOAD}B" if len(data) > MAX_PAYLOAD else ""

    stats["bytes"] += len(data)

    soe_info = ""
    if proto == "UDP":
        soe_info, opcode, _ = parse_soe(data)
        if soe_info and "UNKNOWN" not in soe_info:
            stats["soe_recognized"] += 1

    lines = [f"[{ts}] {proto} {direction} {src}:{sport} → {dst}:{dport}  len={len(data)}"]
    if soe_info:
        lines.append(f"  {soe_info}")
    lines.append(f"  HEX  : {payload_hex}{truncated}")
    lines.append(f"  ASCII: {payload_ascii}{truncated}")

    return "\n".join(lines)


# ── Décodage RC4 en direct ────────────────────────────────────────────────────

def _open_positions_log():
    global positions_log_handle
    positions_log_handle = open(POSITIONS_LOG_FILE, "a", encoding="utf-8", buffering=1)
    positions_log_handle.write(f"\n{'='*70}\n")
    positions_log_handle.write(f"Session : {datetime.now().isoformat()}\n")
    positions_log_handle.write(f"{'='*70}\n\n")


def _handle_appdata(local_port: int, payload: bytes):
    """Logue chaque message applicatif déchiffré. Marque POSITION-PROBABLE si opcode 0x78/0x79."""
    global position_count

    if not payload or positions_log_handle is None:
        return

    first_byte          = payload[0]
    is_probable_position = first_byte in POSITION_BROADCAST_OPCODES
    ts                  = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    tag                 = "[POSITION-PROBABLE]" if is_probable_position else "[appdata]"

    positions_log_handle.write(
        f"[{ts}] {tag} port={local_port} len={len(payload)} opcode=0x{first_byte:02x}\n"
    )
    positions_log_handle.write(f"  HEX  : {payload[:MAX_PAYLOAD].hex()}\n")
    positions_log_handle.write(f"  ASCII: {safe_ascii(payload[:MAX_PAYLOAD])}\n")

    if is_probable_position:
        position_count += 1
        occurrences = payload.count(bytes([first_byte]))
        out_path    = os.path.join(DECODED_DIR, f"position_{position_count:04d}_port{local_port}.bin")

        with open(out_path, "wb") as f:
            f.write(payload)

        positions_log_handle.write(
            f"  -> sauvegardé : {out_path} ({occurrences}x octet 0x{first_byte:02x})\n"
        )
        write(
            f"[POSITION-PROBABLE] port={local_port} len={len(payload)} "
            f"opcode=0x{first_byte:02x} ({occurrences}x) -> {out_path}"
        )


def _feed_reassembly(proto: str, local_is_src: bool, sport: int, dport: int, data: bytes):
    """Ouvre un SOEInputStream au SessionRequest, déchiffre les Data/DataFragment serveur."""
    if proto != "UDP" or len(data) < 4:
        return

    opcode     = struct.unpack(">H", data[:2])[0]
    local_port = sport if local_is_src else dport

    with soe_lock:
        if opcode == 0x0001 and local_is_src:
            if local_port not in soe_channels:
                stream = SOEInputStream(
                    DEFAULT_CRYPTO_KEY,
                    on_appdata=lambda payload, p=local_port: _handle_appdata(p, payload),
                    on_error=lambda msg, p=local_port: write(f"[reassembly-error] port={p} {msg}"),
                )
                stream.set_encryption(True)
                soe_channels[local_port] = stream
                write(f"[*] Canal SOE détecté (port {local_port}) — décodage RC4 démarré")
            return

        if opcode in (0x0009, 0x000D) and not local_is_src:
            stream = soe_channels.get(local_port)
            if stream is None:
                return

            seq = struct.unpack(">H", data[2:4])[0]
            if CRC_LENGTH:
                body = data[4:-CRC_LENGTH]
            else:
                body = data[4:]

            stream.write(body, seq, opcode == 0x000D)


# ── Capture ───────────────────────────────────────────────────────────────────

def _log_packet(cap_dt, proto, src, sport, dst, dport, data, ports_snapshot):
    local_is_src = sport in ports_snapshot
    direction    = "→ SERVER" if local_is_src else "← SERVER"
    remote_ip    = dst if local_is_src else src

    seen_remote_ips.add(remote_ip)
    stats["total"] += 1

    if proto == "UDP":
        stats["udp"] += 1
    else:
        stats["tcp"] += 1

    write(format_packet(proto, direction, src, sport, dst, dport, data, cap_dt=cap_dt))
    _feed_reassembly(proto, local_is_src, sport, dport, data)


def _prune_buffer_locked(now):
    cutoff = now.timestamp() - BUFFER_RETENTION_SECS
    while packet_buffer and packet_buffer[0][0].timestamp() < cutoff:
        packet_buffer.pop(0)


def replay_buffer_for_new_ports(new_port_numbers):
    """Rejoue les paquets en tampon qui concernaient ces ports avant leur détection."""
    with watched_ports_lock:
        ports_snapshot = dict(watched_ports)

    matched   = []
    remaining = []

    with packet_buffer_lock:
        for entry in packet_buffer:
            cap_dt, proto, src, sport, dst, dport, data = entry
            proto_key = proto.lower()
            if (
                (sport in new_port_numbers and ports_snapshot.get(sport) == proto_key)
                or (dport in new_port_numbers and ports_snapshot.get(dport) == proto_key)
            ):
                matched.append(entry)
            else:
                remaining.append(entry)
        packet_buffer[:] = remaining

    if matched:
        write(f"[*] Rejeu rétroactif de {len(matched)} paquet(s)")
        for cap_dt, proto, src, sport, dst, dport, data in matched:
            _log_packet(cap_dt, proto, src, sport, dst, dport, data, ports_snapshot)


def on_packet(pkt):
    # Callback scapy minimal — extrait et enqueue, aucun I/O pour éviter les drops.
    if not (IP in pkt and Raw in pkt):
        return
    try:
        _pkt_queue.put_nowait((
            datetime.now(),
            pkt[IP].src,
            pkt[IP].dst,
            pkt[UDP].sport if UDP in pkt else pkt[TCP].sport,
            pkt[UDP].dport if UDP in pkt else pkt[TCP].dport,
            "UDP" if UDP in pkt else "TCP",
            bytes(pkt[Raw]),
        ))
    except queue.Full:
        pass  # drop explicite plutôt que bloquer le thread scapy


def _packet_worker():
    """Thread qui consomme la queue et fait tout le traitement lourd."""
    while True:
        item = _pkt_queue.get()
        if item is None:
            break

        cap_dt, src, dst, sport, dport, proto, data = item

        with watched_ports_lock:
            ports_snapshot = dict(watched_ports)

        proto_key   = proto.lower()
        proto_match = (
            ports_snapshot.get(sport) == proto_key
            or ports_snapshot.get(dport) == proto_key
        )

        if proto_match:
            _log_packet(cap_dt, proto, src, sport, dst, dport, data, ports_snapshot)
        else:
            with packet_buffer_lock:
                packet_buffer.append((cap_dt, proto, src, sport, dst, dport, data))
                _prune_buffer_locked(cap_dt)


def print_stats():
    write(f"\n{'─'*70}")
    write(f"Session terminée : {datetime.now().isoformat()}")
    write(f"Paquets capturés : {stats['total']} (TCP={stats['tcp']} UDP={stats['udp']})")
    write(f"SOE reconnus     : {stats['soe_recognized']}")
    write(f"Bytes capturés   : {stats['bytes']:,}")
    write(f"IPs distantes    : {sorted(seen_remote_ips)}")

    if stats["udp"] > 0:
        ratio = stats["soe_recognized"] / stats["udp"] * 100
        write(f"Ratio SOE/UDP    : {ratio:.1f}%")

    write(f"\nLog : {os.path.abspath(LOG_FILE)}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(DECODED_DIR, exist_ok=True)
    proc = choose_process()

    poll_thread = threading.Thread(target=poll_ports, args=(proc.pid,), daemon=True)
    poll_thread.start()

    worker_thread = threading.Thread(target=_packet_worker, daemon=True)
    worker_thread.start()

    print("[*] Attente des premiers ports locaux du processus...")
    for _ in range(20):  # jusqu'à 10s
        with watched_ports_lock:
            if watched_ports:
                break
        time.sleep(0.5)

    with watched_ports_lock:
        ports_now = dict(watched_ports)

    if not ports_now:
        print("[!] Aucun port local détecté — la capture démarre quand même.")
    else:
        print(f"[*] Ports surveillés au démarrage : {ports_now}")

    open_log()
    _open_positions_log()
    write(f"Processus surveillé : {proc.info.get('name')} (PID {proc.pid})")
    write("Ctrl+C pour arrêter\n")

    try:
        sniff(filter="net 162.19.0.0/16 and udp", prn=on_packet, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[!] Permission refusée — relancer en administrateur (Windows) / sudo (Linux/Mac)")
        sys.exit(1)
    finally:
        stop_polling.set()
        _pkt_queue.put(None)
        print_stats()
        if log_handle:
            log_handle.close()
        if positions_log_handle:
            positions_log_handle.close()


if __name__ == "__main__":
    main()
