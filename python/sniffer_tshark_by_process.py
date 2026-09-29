"""
sniffer_tshark_by_process.py — Capture pcap via tshark (kernel-level, zéro perte).

Remplace sniffer_by_process.py pour la phase de capture.
Pas de traitement Python live → pas de perte de paquets.
Décode ensuite avec replay_pcap.py.

Usage:
  python sniffer_tshark_by_process.py
  -> attend le process H1Z1, capture tout UDP, sauvegarde game_capture.pcap
  -> Ctrl+C pour arrêter

Ensuite:
  python replay_pcap.py game_capture.pcap
"""

import sys
import os
import time
import subprocess
import threading
import shutil
from datetime import datetime

import psutil

# ── Config ────────────────────────────────────────────────────────────────────
PROCESS_NAME_HINTS   = ["h1z1", "daybreak", "soe", "gamex"]
PROCESS_NAME_EXCLUDE = ["launcher"]
OUTPUT_PCAP          = f"game_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
TSHARK_PATHS         = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "tshark",  # si dans PATH
]
REFRESH_SECS = 0.5
SERVER_IP    = "162.19.94.95"
# ─────────────────────────────────────────────────────────────────────────────


def find_tshark() -> str:
    for path in TSHARK_PATHS:
        if shutil.which(path) or os.path.exists(path):
            return path
    print("[!] tshark introuvable. Installe Wireshark: https://www.wireshark.org/")
    sys.exit(1)


def list_interfaces(tshark: str) -> list[tuple[int, str]]:
    """Retourne [(index, name), ...] depuis tshark -D."""
    try:
        out = subprocess.check_output([tshark, "-D"], text=True, stderr=subprocess.DEVNULL)
        interfaces = []
        for line in out.strip().splitlines():
            parts = line.split(". ", 1)
            if len(parts) == 2:
                try:
                    idx  = int(parts[0])
                    name = parts[1].strip()
                    interfaces.append((idx, name))
                except ValueError:
                    pass
        return interfaces
    except Exception:
        return []


def pick_interface(tshark: str) -> str:
    ifaces = list_interfaces(tshark)
    if not ifaces:
        print("[!] Impossible de lister les interfaces. Utilise l'index 1 par défaut.")
        return "1"

    print("\n[*] Interfaces réseau disponibles:")
    for idx, name in ifaces:
        print(f"  {idx}. {name}")

    # Auto-select : préfère Ethernet / Wi-Fi, exclut loopback et adaptateurs virtuels.
    for idx, name in ifaces:
        n = name.lower()
        if "loopback" in n or "npcap" in n or "adapter for" in n:
            continue
        if "ethernet" in n or "wi-fi" in n or "wifi" in n or "local area" in n:
            print(f"[*] Interface auto-sélectionnée: {idx}. {name}")
            return str(idx)

    choice = input("\nChoisir l'interface (numéro) : ").strip()
    return choice


# ── Détection du processus ───────────────────────────────────────────────────

def find_candidate_processes() -> list[psutil.Process]:
    candidates = []
    for p in psutil.process_iter(["pid", "name", "exe"]):
        name = (p.info.get("name") or "").lower()
        if any(e in name for e in PROCESS_NAME_EXCLUDE):
            continue
        if any(h in name for h in PROCESS_NAME_HINTS):
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
        print(f"  {i:>4}. {p.info['name']:<30} PID={p.info['pid']}")
    while True:
        choice = input("\nChoix (numéro) : ").strip()
        try:
            idx = int(choice)
            if 1 <= idx <= len(procs):
                return procs[idx - 1]
        except ValueError:
            pass


def choose_process() -> psutil.Process:
    print("[*] Recherche du processus H1Z1/ROTK...")
    candidates = find_candidate_processes()

    if len(candidates) == 1:
        p = candidates[0]
        print(f"[*] Processus trouvé: {p.info['name']} (PID {p.info['pid']})")
        return p

    if len(candidates) > 1:
        return pick_from_list(candidates)

    print("[!] Processus non trouvé — en attente du lancement...")
    print("    (Ctrl+C pour sélection manuelle)")
    try:
        attempt = 0
        while True:
            time.sleep(REFRESH_SECS)
            attempt += 1
            candidates = find_candidate_processes()
            if candidates:
                if len(candidates) == 1:
                    p = candidates[0]
                    print(f"\n[*] Processus détecté: {p.info['name']} (PID {p.info['pid']})")
                    return p
                return pick_from_list(candidates)
            if attempt % 20 == 0:
                print(f"[*] En attente... ({attempt * REFRESH_SECS:.0f}s)")
    except KeyboardInterrupt:
        print("\n[*] Sélection manuelle:")
        return pick_from_list(list_all_processes())


# ── Port monitoring ──────────────────────────────────────────────────────────

def get_process_udp_ports(pid: int) -> set[int]:
    try:
        proc  = psutil.Process(pid)
        ports = set()
        for c in proc.net_connections(kind="udp"):
            if c.laddr:
                ports.add(c.laddr.port)
        return ports
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return set()


def monitor_process(pid: int, stop_event: threading.Event):
    """Thread : surveille le process, set stop_event quand il meurt."""
    while not stop_event.is_set():
        try:
            psutil.Process(pid)
        except psutil.NoSuchProcess:
            print("\n[!] Processus terminé. Arrêt de la capture.")
            stop_event.set()
            return
        time.sleep(1.0)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    tshark = find_tshark()
    print(f"[*] tshark trouvé: {tshark}")

    iface = pick_interface(tshark)
    proc  = choose_process()
    pid   = proc.info["pid"]

    print(f"\n[*] Capture sur interface {iface} → {OUTPUT_PCAP}")
    print(f"[*] Process: {proc.info['name']} (PID {pid})")
    print(f"[*] Filtre: tout UDP (filtrage par IP serveur {SERVER_IP} fait offline)")
    print("[*] Lance le jeu et joue. Ctrl+C pour arrêter.\n")

    print("[*] En attente de connexions UDP du process...")
    while True:
        ports = get_process_udp_ports(pid)
        if ports:
            print(f"[*] Ports UDP détectés: {sorted(ports)}")
            break
        time.sleep(0.2)

    cmd = [
        tshark,
        "-i", iface,
        "-f", "udp",
        "-w", OUTPUT_PCAP,
        "-q",
    ]
    print(f"[*] Commande: {' '.join(cmd)}\n")

    stop_event  = threading.Event()
    tshark_proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)

    monitor_thread = threading.Thread(
        target=monitor_process, args=(pid, stop_event), daemon=True
    )
    monitor_thread.start()

    def port_watcher():
        known = set()
        while not stop_event.is_set():
            ports = get_process_udp_ports(pid)
            new   = ports - known
            if new:
                print(f"[+] Nouveaux ports UDP: {sorted(new)}")
                known = ports
            time.sleep(1.0)

    port_thread = threading.Thread(target=port_watcher, daemon=True)
    port_thread.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
            if tshark_proc.poll() is not None:
                print("[!] tshark s'est arrêté de façon inattendue.")
                break
    except KeyboardInterrupt:
        print("\n[*] Arrêt demandé.")
    finally:
        stop_event.set()
        tshark_proc.terminate()
        try:
            tshark_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            tshark_proc.kill()

    if os.path.exists(OUTPUT_PCAP):
        size = os.path.getsize(OUTPUT_PCAP)
        print(f"\n[+] Capture sauvegardée: {OUTPUT_PCAP} ({size / 1024 / 1024:.1f} MB)")
        print(f"\n[*] Étape suivante :")
        print(f"    python replay_pcap.py {OUTPUT_PCAP}")
    else:
        print("[!] Fichier pcap non créé. Vérifie les droits administrateur.")


if __name__ == "__main__":
    main()
