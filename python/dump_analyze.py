#!/usr/bin/env python3
"""
dump_analyze.py — Analyse les dumps de payloads zone de RadarPoC.

Usage: python3 dump_analyze.py <dumps/<session>/>

Pour chaque répertoire d'opcode, sonde les offsets candidats pour décoder
un transient-id (uint2bit). Les opcodes broadcast joueur produisent beaucoup
de tids distincts dans un range raisonnable (1..100k) ; le bruit en produit 1-2.
"""
from __future__ import annotations

import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional


def read_uint2bit(buf: bytes, off: int) -> Optional[tuple[int, int]]:
    """Décode readUnsignedIntWith2bitLengthValue à l'offset donné. Retourne (val, next_off) ou None."""
    if off < 0 or off >= len(buf):
        return None

    first = buf[off]
    extra = first & 3
    end   = off + extra + 1

    if end > len(buf):
        return None

    val = first
    for i in range(extra):
        val += buf[off + 1 + i] << ((i + 1) * 8)

    return (val >> 2, end)


def analyze_opcode_dir(op_dir: Path) -> dict:
    """Retourne un dict diagnostique pour un répertoire d'opcode."""
    files    = sorted(op_dir.glob("*.bin"))
    sizes    = []
    prefixes = Counter()
    tids_by_off: dict[int, set[int]] = defaultdict(set)

    # Offsets candidats pour le début du transient-id selon le format :
    #   tunnel gw(1)+length(4)+opcode(1)+tid → offset 6
    #   tunnel 2-byte length → offset 4
    #   après zone opcode (raw ou ch2) → offset 2
    #   ch2 direct → offset 1
    candidate_offsets = [1, 2, 3, 4, 5, 6, 7, 8]

    for f in files:
        data = f.read_bytes()
        sizes.append(len(data))
        prefixes[data[:8].hex()] += 1

        for off in candidate_offsets:
            r = read_uint2bit(data, off)
            if r is None:
                continue

            tid, _ = r
            # H1Z1 tids sont généralement < 65536 — hors range = garbage.
            if 1 <= tid <= 100_000:
                tids_by_off[off].add(tid)

    if tids_by_off:
        best_off = max(tids_by_off, key=lambda o: len(tids_by_off[o]))
    else:
        best_off = None

    return {
        "files":         len(files),
        "min_size":      min(sizes) if sizes else 0,
        "max_size":      max(sizes) if sizes else 0,
        "avg_size":      sum(sizes) // len(sizes) if sizes else 0,
        "top_prefixes":  prefixes.most_common(3),
        "best_off":      best_off,
        "best_tid_count": len(tids_by_off[best_off]) if best_off is not None else 0,
        "tid_diversity": {off: len(s) for off, s in sorted(tids_by_off.items()) if len(s) > 0},
    }


def main(root: str) -> int:
    root_path = Path(root)

    if not root_path.exists():
        print(f"error: {root_path} does not exist", file=sys.stderr)
        return 2

    op_dirs = [d for d in sorted(root_path.iterdir()) if d.is_dir()]
    if not op_dirs:
        print(f"error: no opcode subdirs in {root_path}", file=sys.stderr)
        return 2

    rows = []
    for op_dir in op_dirs:
        rows.append((op_dir.name, analyze_opcode_dir(op_dir)))

    # Meilleurs candidats en premier (plus de tids distincts = plus probable broadcast joueur).
    rows.sort(key=lambda r: r[1]["best_tid_count"], reverse=True)

    print(f"{'tag':22s} {'files':>5s} {'size(min/avg/max)':>18s} {'off':>4s} {'tids':>5s}  prefixes")
    print("-" * 100)

    for tag, r in rows:
        size_str = f"{r['min_size']}/{r['avg_size']}/{r['max_size']}"
        if r["best_off"] is not None:
            off_str = str(r["best_off"])
        else:
            off_str = "-"
        prefixes = " ".join(p for p, _ in r["top_prefixes"])
        print(f"{tag:22s} {r['files']:>5d} {size_str:>18s} {off_str:>4s} {r['best_tid_count']:>5d}  {prefixes}")

    print()
    print("Interpretation:")
    print("  tids >= 50  = strong candidate for player broadcast")
    print("  tids 10-50  = maybe per-entity update (movement, animation)")
    print("  tids < 10   = noise / fixed-header opcode / non-player packet")

    print()
    print("Top candidate detail:")
    if rows and rows[0][1]["best_tid_count"] > 10:
        tag, r = rows[0]
        print(f"  {tag}: best_off={r['best_off']}, tids={r['best_tid_count']}")
        print(f"  offset diversity map: {r['tid_diversity']}")

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
