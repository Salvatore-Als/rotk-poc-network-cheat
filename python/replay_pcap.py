"""
replay_pcap.py — Analyse offline d'un fichier pcap capturé par Wireshark.

Usage:
  1. Capturer avec Wireshark (filtre: "udp and host 162.19.94.95")
  2. Sauvegarder en .pcap ou .pcapng
  3. python replay_pcap.py <fichier.pcap>
"""

import struct
import sys
import os
from datetime import datetime

from scapy.all import rdpcap, UDP, IP, Raw
from soe_reassembly import SOEInputStream, DEFAULT_CRYPTO_KEY, POSITION_BROADCAST_OPCODES
from h1z1_position_parser import parse_position_broadcasts, format_entry

# ── Config ────────────────────────────────────────────────────────────────────
SERVER_IP         = "162.19.94.95"
CRC_LENGTH        = 2
DECODED_DIR       = "decoded_packets_offline"
POSITIONS_LOG     = "rotk-positions-offline.log"
MAX_HEX_LOG       = 4096
ZONE_POSITION_OPCODE = 0x79  # byte[1] du payload déchiffré (après gateway byte)
# ─────────────────────────────────────────────────────────────────────────────

soe_channels: dict[int, SOEInputStream] = {}
position_count = 0
log_handle = None
_current_ts = [0.0]  # mutable box pour que les lambdas puissent le lire


def open_log():
    global log_handle
    os.makedirs(DECODED_DIR, exist_ok=True)
    log_handle = open(POSITIONS_LOG, "w", encoding="utf-8", buffering=1)
    log_handle.write(f"{'='*70}\n")
    log_handle.write(f"Replay offline : {datetime.now().isoformat()}\n")
    log_handle.write(f"{'='*70}\n\n")


def handle_appdata(local_port: int, payload: bytes, ts: float):
    """Appel pour chaque message applicatif déchiffré."""
    global position_count

    if not payload or log_handle is None:
        return

    gw_byte  = payload[0]
    zone_op  = payload[1] if len(payload) >= 2 else 0
    is_position = zone_op == ZONE_POSITION_OPCODE

    time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
    tag = "[POSITION]" if is_position else "[appdata]"

    log_handle.write(
        f"[{time_str}] {tag} port={local_port} len={len(payload)} "
        f"gw=0x{gw_byte:02x} zone_op=0x{zone_op:02x}\n"
    )
    log_handle.write(f"  HEX  : {payload[:MAX_HEX_LOG].hex()}\n")

    if is_position:
        position_count += 1
        zone_data = payload[1:]  # skip gateway byte
        entries, consumed = parse_position_broadcasts(zone_data)

        log_handle.write(f"  -> {len(entries)} joueurs parsés, {consumed}/{len(zone_data)} bytes\n")

        for tid, fields in entries:
            line = format_entry(tid, fields)
            log_handle.write(f"  -> {line}\n")
            print(f"  [position] port={local_port} {line}")

        if entries:
            out_path = os.path.join(DECODED_DIR, f"pos_{position_count:04d}_port{local_port}.bin")
            with open(out_path, "wb") as f:
                f.write(zone_data)
            log_handle.write(f"  -> sauvegardé : {out_path}\n")

    log_handle.write("\n")


def feed_packet(pkt, local_ip: str):
    """Traite un paquet UDP depuis le pcap."""
    if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
        return

    data = bytes(pkt[Raw].load)
    if len(data) < 4:
        return

    opcode       = struct.unpack(">H", data[:2])[0]
    sport        = pkt[UDP].sport
    dport        = pkt[UDP].dport
    local_is_src = pkt[IP].src == local_ip
    local_port   = sport if local_is_src else dport

    # SessionRequest → initialise le canal SOE pour ce port.
    if opcode == 0x0001 and local_is_src:
        if local_port not in soe_channels:
            port   = local_port
            stream = SOEInputStream(
                DEFAULT_CRYPTO_KEY,
                on_appdata=lambda payload, p=port: handle_appdata(p, payload, _current_ts[0]),
                on_error=lambda msg, p=port: print(f"[reassembly-err] port={p} {msg}"),
            )
            stream.set_encryption(True)
            soe_channels[local_port] = stream
            print(f"[*] Canal SOE initialisé: port {local_port}")
        return

    # Data / DataFragment serveur → déchiffrement RC4.
    if opcode in (0x0009, 0x000D) and not local_is_src:
        stream = soe_channels.get(local_port)
        if stream is None:
            return

        seq = struct.unpack(">H", data[2:4])[0]
        if CRC_LENGTH:
            body = data[4:-CRC_LENGTH]
        else:
            body = data[4:]

        _current_ts[0] = float(pkt.time)
        stream.write(body, seq, opcode == 0x000D)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <fichier.pcap>")
        print("Capturez avec Wireshark: filtre = 'udp and host 162.19.94.95'")
        sys.exit(1)

    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(f"Fichier introuvable: {pcap_file}")
        sys.exit(1)

    print(f"[*] Lecture pcap: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] {len(packets)} paquets chargés")

    # Déterminer l'IP locale depuis le premier paquet vers/depuis le serveur.
    local_ip = None
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
            continue
        if pkt[IP].dst == SERVER_IP:
            local_ip = pkt[IP].src
            break
        if pkt[IP].src == SERVER_IP:
            local_ip = pkt[IP].dst
            break

    if not local_ip:
        print("[!] Impossible de déterminer l'IP locale. Vérifiez SERVER_IP.")
        sys.exit(1)

    print(f"[*] IP locale: {local_ip}")
    open_log()

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
            continue
        try:
            feed_packet(pkt, local_ip)
        except Exception:
            pass

    print(f"\n[*] Terminé. {position_count} position broadcasts trouvés.")
    print(f"[*] Log: {POSITIONS_LOG}")
    print(f"[*] Fichiers: {DECODED_DIR}/")

    if log_handle:
        log_handle.close()


if __name__ == "__main__":
    main()
