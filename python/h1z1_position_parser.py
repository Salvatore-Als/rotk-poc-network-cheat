"""
h1z1_position_parser.py — Décode les paquets PlayerUpdatePosition (opcode 0x79).

Port de https://github.com/H1emu/h1z1-server (shared.ts / base.ts).
Un paquet SOE peut contenir plusieurs updates concaténées — parse_position_broadcasts()
les extrait toutes.
"""

import struct

PLAYER_UPDATE_POSITION_OPCODE = 0x79


def read_unsigned_int_2bit(data: bytes, offset: int):
    value = data[offset]
    n = value & 3

    for i in range(n):
        value += data[offset + i + 1] << ((i + 1) * 8)

    value = value >> 2
    return value, n + 1


def read_signed_int_2bit(data: bytes, offset: int):
    value = data[offset]
    sign = value & 1
    n = (value >> 1) & 3

    for i in range(n):
        value += data[offset + i + 1] << ((i + 1) * 8)

    value = value >> 3

    if sign:
        value = -value

    return value, n + 1


def read_position_update_data(data: bytes, offset: int):
    """Miroir de readPositionUpdateData (shared.ts). L'ordre des flags doit rester identique au source."""
    start = offset
    obj = {}

    flags = int.from_bytes(data[offset:offset + 2], "little")
    offset += 2
    obj["flags"] = flags

    obj["sequenceTime"] = int.from_bytes(data[offset:offset + 4], "little")
    offset += 4

    obj["unknown3_int8"] = data[offset]
    offset += 1

    if flags & 0x1:
        v, n = read_unsigned_int_2bit(data, offset)
        obj["stance"] = v
        offset += n

    if flags & 0x2:
        pos = [0.0, 0.0, 0.0]
        for i in range(3):
            v, n = read_signed_int_2bit(data, offset)
            pos[i] = v / 100
            offset += n
        obj["position"] = pos

    if flags & 0x20:
        obj["orientation"] = struct.unpack_from("<f", data, offset)[0]
        offset += 4

    if flags & 0x40:
        v, n = read_signed_int_2bit(data, offset)
        obj["frontTilt"] = v / 100
        offset += n

    if flags & 0x80:
        v, n = read_signed_int_2bit(data, offset)
        obj["sideTilt"] = v / 100
        offset += n

    if flags & 0x4:
        v, n = read_signed_int_2bit(data, offset)
        obj["angleChange"] = v / 100
        offset += n

    if flags & 0x8:
        v, n = read_signed_int_2bit(data, offset)
        obj["verticalSpeed"] = v / 100
        offset += n

    if flags & 0x10:
        v, n = read_signed_int_2bit(data, offset)
        obj["horizontalSpeed"] = v / 10
        offset += n

    if flags & 0x100:
        vals = [0.0, 0.0, 0.0]
        for i in range(3):
            v, n = read_signed_int_2bit(data, offset)
            vals[i] = v / 100
            offset += n
        obj["unknown12_float"] = vals

    if flags & 0x200:
        vals = [0.0, 0.0, 0.0, 0.0]
        for i in range(4):
            v, n = read_signed_int_2bit(data, offset)
            vals[i] = v / 100
            offset += n
        obj["rotationRaw"] = vals

    if flags & 0x400:
        v, n = read_signed_int_2bit(data, offset)
        obj["direction"] = v / 10
        offset += n

    if flags & 0x800:
        v, n = read_signed_int_2bit(data, offset)
        obj["engineRPM"] = v / 10
        offset += n

    # ROTK (KOTK) : flag 0x1000 présent dans les données mais ne consomme aucun byte.
    # h1z1-server Just Survive lit 8 valeurs ici, KOTK ne le fait pas.
    # Lire ces bytes désynchronise tout le parsing — comportement KOTK par défaut.
    if flags & 0x1000:
        obj["_flag_0x1000_present_mais_non_lu_KOTK"] = True

    return obj, offset - start


def parse_position_broadcasts(data: bytes):
    """Extrait toutes les entrées PlayerUpdatePosition (0x79) au début du buffer.
    Retourne (entries, nb_octets_consommés). S'arrête au premier opcode inconnu."""
    entries = []
    offset = 0
    n = len(data)

    while offset < n and data[offset] == PLAYER_UPDATE_POSITION_OPCODE:
        entry_start = offset
        try:
            offset += 1
            transient_id, consumed = read_unsigned_int_2bit(data, offset)
            offset += consumed
            fields, consumed2 = read_position_update_data(data, offset)
            offset += consumed2
        except IndexError:
            offset = entry_start
            break

        entries.append((transient_id, fields))

    return entries, offset


def format_entry(transient_id: int, fields: dict) -> str:
    parts = [f"id={transient_id}"]

    if "position" in fields:
        x, y, z = fields["position"]
        parts.append(f"pos=({x:.2f}, {y:.2f}, {z:.2f})")
    if "orientation" in fields:
        parts.append(f"orient={fields['orientation']:.2f}")
    if "stance" in fields:
        parts.append(f"stance={fields['stance']}")
    if "direction" in fields:
        parts.append(f"dir={fields['direction']:.2f}")
    if "horizontalSpeed" in fields:
        parts.append(f"hspeed={fields['horizontalSpeed']:.2f}")
    if "verticalSpeed" in fields:
        parts.append(f"vspeed={fields['verticalSpeed']:.2f}")

    return " ".join(parts)
