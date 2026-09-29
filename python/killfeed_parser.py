#!/usr/bin/env python3
"""
killfeed_parser.py — Extrait kills, chat et noms de joueurs depuis un pcap ROTK/H1Z1.

Usage: python killfeed_parser.py <fichier.pcap> [--debug-d6]

Passes :
  1. Extrait la clé RC4 depuis LoginUdp (CharacterLoginReply)
  2. Déchiffre les canaux zone → parse kills, noms, chat, positions
"""

import struct
import sys
import os
import base64
from datetime import datetime

try:
    from scapy.all import rdpcap, UDP, IP, Raw
except ImportError:
    print("[!] scapy non installé : pip install scapy")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(__file__))
from soe_reassembly import SOEInputStream, DEFAULT_CRYPTO_KEY
from h1z1_position_parser import parse_position_broadcasts

CRC_LENGTH   = 2
GATEWAY_PORT = 20145
DEBUG_D6     = "--debug-d6" in sys.argv


# ── Helpers binaires ──────────────────────────────────────────────────────────

def u8(d, o):
    if o < len(d):
        return d[o], o + 1
    return None, o


def u32le(d, o):
    if o + 4 <= len(d):
        return struct.unpack_from('<I', d, o)[0], o + 4
    return None, o


def u64le(d, o):
    if o + 8 <= len(d):
        return struct.unpack_from('<Q', d, o)[0], o + 8
    return None, o


def str_utf8(d, o):
    """uint32 LE length + UTF-8 bytes."""
    n, o = u32le(d, o)
    if n is None or n > 512 or o + n > len(d):
        return None, o
    try:
        return d[o:o + n].decode('utf-8', errors='replace'), o + n
    except Exception:
        return None, o + n


def uint2bit(d, o):
    if o >= len(d):
        return None, o

    b = d[o]
    n = b & 3
    v = b

    for i in range(n):
        if o + i + 1 >= len(d):
            return None, o
        v += d[o + i + 1] << ((i + 1) * 8)

    return v >> 2, o + n + 1


def scan_strings(d, start, min_len=3):
    """Scanne les strings UTF-8 length-prefixed dans un buffer."""
    out = []
    o = start

    while o + 4 < len(d):
        n, _ = u32le(d, o)
        if n and min_len <= n <= 256 and o + 4 + n <= len(d):
            chunk = d[o + 4:o + 4 + n]
            try:
                s = chunk.decode('utf-8')
                if all(0x20 <= ord(c) <= 0x7E for c in s):
                    out.append(s)
                    o += 4 + n
                    continue
            except Exception:
                pass
        o += 1

    return out


# ── Extraction clé RC4 ────────────────────────────────────────────────────────

def try_extract_key(data):
    """Cherche le pattern CharacterLoginReply (address + ticket + key16) dans un payload LoginUdp."""
    for off in range(len(data) - 30):
        addr_len, _ = u32le(data, off)
        if addr_len is None or not (7 <= addr_len <= 64):
            continue
        if off + 4 + addr_len + 8 > len(data):
            continue

        addr = data[off + 4:off + 4 + addr_len]
        if b':' not in addr or not all(0x20 <= b <= 0x7E for b in addr):
            continue

        tick_off = off + 4 + addr_len
        tick_len, _ = u32le(data, tick_off)
        if tick_len is None or not (1 <= tick_len <= 512):
            continue

        key_off = tick_off + 4 + tick_len
        if key_off + 4 > len(data):
            continue

        key_len, _ = u32le(data, key_off)
        if key_len != 16 or key_off + 4 + 16 > len(data):
            continue

        return data[key_off + 4:key_off + 4 + 16], addr.decode('ascii')

    return None, None


# ── Parsers appdata zone ──────────────────────────────────────────────────────

def parse_killed_by(data, ts, char_names, kills_out):
    """0x0F 0x48 — [gw][0F][48][killer:u64][killed:u64][cheater:u8]"""
    if len(data) < 20:
        return

    killer, _ = u64le(data, 3)
    killed, _ = u64le(data, 11)
    k1 = char_names.get(killer, f"id:{killer}")
    k2 = char_names.get(killed, f"id:{killed}")

    line = f"[{ts}] 💀  {k1}  →  {k2}"
    print(line)
    kills_out.append(line)


def parse_death_info(data, ts, char_names, kills_out):
    """0xCF 0x04 0x00 — BR death info avec playerName du tueur."""
    off = 4
    pos_idx, off = u32le(data, off)
    _, off = u8(data, off)
    name, _ = str_utf8(data, off)

    if name:
        line = f"[{ts}] ☠  DeathInfo tueur={name}  rank={pos_idx}"
        print(line)
        kills_out.append(line)


def parse_add_lightweight_pc(data, ts, char_names):
    """0xD6 — AddLightweightPc : [gw][D6][charId:u64][transientId:uint2bit][identity...]"""
    off = 2
    char_id, off = u64le(data, off)
    if char_id is None:
        return

    _, off = uint2bit(data, off)

    if DEBUG_D6:
        print(f"  [D6 RAW] len={len(data)} id={char_id} hex={data[:min(64, len(data))].hex()}")

    # identity : 3 × uint32 inconnus (padding)
    off += 12
    if off > len(data):
        return

    first_name, off = str_utf8(data, off)
    last_name,  off = str_utf8(data, off)
    steam_id,   off = str_utf8(data, off)
    char_name,  off = str_utf8(data, off)

    name = char_name or first_name or None

    if not name:
        # Format ROTK peut différer — scan brut en fallback
        found = scan_strings(data, start=10, min_len=3)
        name = next((s for s in found if len(s) >= 3), None)
        if name and DEBUG_D6:
            print(f"  [D6 scan] trouvé via scan brut: {found}")

    if name and char_id:
        char_names[char_id] = name
        s_part = ""
        if steam_id:
            s_part = f"  steam={steam_id}"
        print(f"[{ts}] 👤  {name}  (id={char_id}{s_part})")


def parse_chat(data, ts):
    """0x06 XX 00 — Chat (scan des strings UTF-8 dans le payload)."""
    if len(data) < 5:
        return

    sub = (data[2], data[3])
    if sub not in ((0x01, 0x00), (0x05, 0x00), (0x06, 0x00)):
        return

    strings = scan_strings(data, start=4, min_len=4)
    readable = [s for s in strings if len(s) >= 4]

    if readable:
        print(f"[{ts}] 💬  Chat: " + " | ".join(readable))


def parse_positions(data, ts, port):
    """0x79 — positions joueurs."""
    entries, _ = parse_position_broadcasts(data[1:])

    for tid, fields in entries:
        if 'position' not in fields:
            continue
        x, y, z = fields['position']
        # Filtre garbage : coords dans les bornes de la map (~6144m)
        if -3000 <= x <= 9000 and -200 <= y <= 1000 and -3000 <= z <= 9000:
            print(f"[{ts}] 📍  tid={tid}  ({x:.1f},{y:.1f},{z:.1f})  [:{port}]")


def make_zone_cb(port, char_names, kills_out):
    def cb(data):
        if len(data) < 2:
            return

        ts = getattr(cb, '_ts', '??:??:??')
        op1 = data[1]
        op2 = data[2] if len(data) > 2 else 0
        op3 = data[3] if len(data) > 3 else 0

        if op1 == 0x0F and op2 == 0x48:
            parse_killed_by(data, ts, char_names, kills_out)
        elif op1 == 0xCF and op2 == 0x04 and op3 == 0x00:
            parse_death_info(data, ts, char_names, kills_out)
        elif op1 == 0xD6:
            parse_add_lightweight_pc(data, ts, char_names)
        elif op1 == 0x06:
            parse_chat(data, ts)
        elif op1 == 0x79:
            parse_positions(data, ts, port)

    return cb


# ── SessionRequest / SessionReply helpers ─────────────────────────────────────

def read_session_protocol(payload):
    H = 14
    if len(payload) <= H:
        return None

    end = payload.find(b'\x00', H)
    if end <= H:
        return None

    try:
        s = payload[H:end].decode('ascii')
        if all(0x20 <= ord(c) <= 0x7E for c in s):
            return s
        return None
    except Exception:
        return None


def feed_packet(data, stream, has_comp, crc):
    opcode = (data[0] << 8) | data[1]
    if opcode not in (0x0009, 0x000D):
        return False

    seq_off  = 3 if has_comp else 2
    body_off = seq_off + 2
    if len(data) - body_off - crc <= 0:
        return False

    seq  = struct.unpack('>H', data[seq_off:seq_off + 2])[0]
    body = data[body_off:len(data) - crc]

    try:
        stream.write(body, seq, opcode == 0x000D)
    except Exception:
        pass

    return True


# ── Passe 1 : extraction clé ──────────────────────────────────────────────────

def pass1_extract_key(packets, local_ip):
    print("[*] Passe 1 : extraction clé RC4 depuis LoginUdp...")

    key_found    = [None]
    login_port   = None
    login_comp   = None
    login_crc    = CRC_LENGTH
    login_stream = None

    def cb(data):
        if key_found[0] is not None:
            return
        k, addr = try_extract_key(data)
        if k:
            key_found[0] = k
            print(f"    ✓ Clé RC4 : {base64.b64encode(k).decode()}")
            print(f"    ✓ Adresse zone : {addr}\n")

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            continue

        data = bytes(pkt[Raw].load)
        if len(data) < 4:
            continue

        sport  = pkt[UDP].sport
        dport  = pkt[UDP].dport
        is_cli = pkt[IP].src == local_ip
        lport  = sport if is_cli else dport
        opcode = (data[0] << 8) | data[1]

        if opcode == 0x0001 and is_cli and login_stream is None:
            proto = read_session_protocol(data)
            if proto and proto.startswith('LoginUdp'):
                login_port   = sport
                login_stream = SOEInputStream(DEFAULT_CRYPTO_KEY, on_appdata=cb, on_error=lambda m: None)
                login_stream.set_encryption(True)
                print(f"    → LoginUdp sur :{login_port}")
            continue

        if login_stream is None or lport != login_port:
            continue

        if opcode == 0x0002 and not is_cli and len(data) >= 13:
            login_comp = data[11] != 0
            login_crc  = data[10]
            continue

        if not is_cli:
            feed_packet(data, login_stream, login_comp or False, login_crc)

        if key_found[0]:
            break

    if key_found[0] is None:
        print("    [!] Clé non trouvée — ce pcap ne contient peut-être pas CharacterLoginReply")
        print("         (session déjà établie avant le début de la capture)\n")

    return key_found[0]


# ── Passe 2 : parsing complet ─────────────────────────────────────────────────

def pass2_parse(packets, local_ip, gateway_key):
    print("[*] Passe 2 : déchiffrement et parsing des canaux zone...")

    if gateway_key is None:
        print("    [!] Pas de clé → essai avec DEFAULT_CRYPTO_KEY (résultats peut-être garbage)")
        gateway_key = DEFAULT_CRYPTO_KEY

    streams    = {}   # port → SOEInputStream
    cbs        = {}   # port → callback (pour injecter le timestamp)
    comp_map   = {}   # port → bool (compression activée)
    crc_map    = {}   # port → int (longueur CRC)
    char_names = {}   # characterId → name
    kills      = []

    def open_session(local_port, server_ip, server_port, protocol):
        if protocol.startswith('IpPingServiceUdp'):
            return

        if protocol.startswith('LoginUdp'):
            key = DEFAULT_CRYPTO_KEY
            cb  = lambda data: None
        elif server_port == GATEWAY_PORT:
            key = gateway_key
            cb  = lambda data: None
        else:
            key = gateway_key
            cb  = make_zone_cb(local_port, char_names, kills)
            cbs[local_port] = cb
            print(f"    [ZONE] :{local_port} → {server_ip}:{server_port}")

        s = SOEInputStream(key, on_appdata=cb, on_error=lambda m: None)
        s.set_encryption(True)
        streams[local_port]  = s
        comp_map[local_port] = False
        crc_map[local_port]  = CRC_LENGTH

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            continue

        data   = bytes(pkt[Raw].load)
        if len(data) < 4:
            continue

        sport  = pkt[UDP].sport
        dport  = pkt[UDP].dport
        is_cli = pkt[IP].src == local_ip
        lport  = sport if is_cli else dport
        opcode = (data[0] << 8) | data[1]
        ts_str = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]

        if lport in cbs:
            cbs[lport]._ts = ts_str

        if opcode == 0x0001 and is_cli:
            if lport not in streams:
                proto = read_session_protocol(data)
                if proto:
                    open_session(lport, pkt[IP].dst, dport, proto)
            continue

        if opcode == 0x0002 and not is_cli and len(data) >= 13:
            comp_map[lport] = data[11] != 0
            crc_map[lport]  = data[10]
            continue

        if opcode not in (0x0009, 0x000D) or is_cli:
            continue

        stream = streams.get(lport)
        if stream is None:
            continue

        feed_packet(data, stream, comp_map.get(lport, False), crc_map.get(lport, CRC_LENGTH))

    return char_names, kills


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <fichier.pcap> [--debug-d6]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    print(f"[*] Lecture pcap : {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] {len(packets)} paquets chargés\n")

    # IP locale = source du premier SessionRequest (opcode 0x00 0x01)
    local_ip = next(
        (pkt[IP].src for pkt in packets
         if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw)
         and len(bytes(pkt[Raw].load)) >= 2
         and bytes(pkt[Raw].load)[0] == 0x00
         and bytes(pkt[Raw].load)[1] == 0x01),
        None
    )

    if not local_ip:
        print("[!] IP locale introuvable")
        sys.exit(1)

    print(f"[*] IP locale : {local_ip}\n")

    key          = pass1_extract_key(packets, local_ip)
    names, kills = pass2_parse(packets, local_ip, key)

    print(f"\n{'='*60}")
    print(f"[RÉSUMÉ] Joueurs indexés (0xD6) : {len(names)}")
    for cid, name in sorted(names.items(), key=lambda x: x[1])[:40]:
        print(f"    {name:35s} id={cid}")

    print(f"\n[RÉSUMÉ] Kills / Death events : {len(kills)}")
    for k in kills:
        print(f"    {k}")

    if not kills and not names:
        print("\n[?] Rien trouvé. Raisons probables :")
        print("    • La clé n'a pas été extraite → données chiffrées avec mauvaise clé")
        print("    • Ce pcap est uniquement lobby (pas de kills)")
        print("    • Relancer avec --debug-d6 pour voir les bytes bruts des 0xD6")


if __name__ == '__main__':
    main()
