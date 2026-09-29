namespace RadarPoC.Services;

// Parser de positions H1Z1/ROTK (zone opcode 0x79 = PlayerUpdatePosition).
//
// Layout appdata déchiffré : [gw byte][0x79][stream d'entrées : [0x79][tid][flags][data...]]
//
// ROTK : flags 0x800 et 0x1000+ présents dans les données mais ne consomment aucun byte
// (contrairement à h1z1-server Just Survive). Découvert empiriquement sur trafic réel.
public static class PositionParser
{
    private const byte PositionOpcode = 0x79;

    public readonly record struct Entry(int TransientId, float? X, float? Y, float? Z, ushort Flags);

    // Format position fixe 25 bytes (gw=0x45, marker 19 03 04).
    // Layout: [0x45][tid u32][per-player byte][flags 5B][seq u16][19 03 04][X u24][Z u16][0x06][Y u16][0x3b]
    // Coords en cm → /100 pour mètres.
    public static Entry? ParsePositionBroadcast25(byte[] payload)
    {
        if (payload.Length != 25
            || payload[0] != 0x45
            || payload[13] != 0x19
            || payload[14] != 0x03
            || payload[15] != 0x04
            || payload[21] != 0x06
            || payload[24] != 0x3b)
        {
            return null;
        }

        int target = payload[1]
                   | (payload[2] << 8)
                   | (payload[3] << 16)
                   | (payload[4] << 24);
        int x = payload[16] | (payload[17] << 8) | (payload[18] << 16);
        int z = payload[19] | (payload[20] << 8);
        int y = payload[22] | (payload[23] << 8);

        return new Entry(target, x / 100f, y / 100f, z / 100f, Flags: 0x0002);
    }

    // Format position variable opAE (gw=0x45, marker 22 03 78).
    // Layout: [0x45][tid u32][char_id upper u32][flags u16][seq u16][22 03 78][s2bit varints...]
    // Ordre des coords: decoded[0]=N/S, [1]=altitude, [2]=E/W → remappé X=E/W, Y=N/S, Z=altitude.
    public static Entry? ParsePositionOpAE(byte[] payload)
    {
        if (payload.Length < 19
            || payload[0] != 0x45
            || payload[13] != 0x22
            || payload[14] != 0x03
            || payload[15] != 0x78)
        {
            return null;
        }

        ushort flags = (ushort)(payload[9] | (payload[10] << 8));
        if ((flags & 0x0002) == 0)
        {
            return null;
        }

        int tid = payload[1] | (payload[2] << 8) | (payload[3] << 16) | (payload[4] << 24);

        int off = 16;
        try
        {
            if ((flags & 0x0001) != 0)
            {
                ReadUnsignedInt2Bit(payload, ref off); // stance — skip
            }

            int rawX = ReadSignedInt2Bit(payload, ref off); // N/S
            int rawY = ReadSignedInt2Bit(payload, ref off); // altitude
            int rawZ = ReadSignedInt2Bit(payload, ref off); // E/W

            // Remap to Radar convention: Entry.X=E/W, Entry.Y=N/S, Entry.Z=altitude
            return new Entry(tid, rawZ / 100f, rawX / 100f, rawY / 100f, flags);
        }
        catch
        {
            return null;
        }
    }

    private static int ReadUnsignedInt2Bit(byte[] data, ref int off)
    {
        int b = data[off];
        int n = b & 3;
        uint val = (uint)b;
        for (int i = 0; i < n; i++)
        {
            val |= (uint)data[off + i + 1] << ((i + 1) * 8);
        }
        off += n + 1;
        return (int)(val >> 2);
    }

    private static int ReadSignedInt2Bit(byte[] data, ref int off)
    {
        int b = data[off];
        int sign = b & 1;
        int n = (b >> 1) & 3;
        uint val = (uint)b;
        for (int i = 0; i < n; i++)
        {
            val |= (uint)data[off + i + 1] << ((i + 1) * 8);
        }
        off += n + 1;
        int result = (int)(val >> 3);
        return sign != 0 ? -result : result;
    }

    // Surcharge : parse depuis un offset arbitraire (byte[0] = opcode directement).
    public static List<Entry> ParseFromOffset(byte[] payload, int startOffset)
    {
        return ParsePositionStream(payload, startOffset);
    }

    // Canal 2 gateway : pas d'opcode 0x79 — payload[offset] = début du transientId.
    // Une trame peut contenir plusieurs updates concaténées.
    public static Entry? ParseSingleEntryDirect(byte[] payload, int startOffset)
    {
        var list = ParseDirectStream(payload, startOffset);
        return list.Count > 0 ? list[0] : null;
    }

    public static List<Entry> ParseDirectStream(byte[] payload, int startOffset)
    {
        var entries = new List<Entry>();
        int offset = startOffset;

        while (offset + 8 < payload.Length)
        {
            int entryStart = offset;
            try
            {
                int transientId = ReadUnsignedInt2bit(payload, ref offset);
                Entry entry = ReadPositionUpdateData(payload, ref offset, transientId);

                // Garde-fou : une vraie update position a le flag 0x2.
                // Sans ça on accepte des paquets non-position mal interprétés → hors-bornes.
                if ((entry.Flags & 0x0002) == 0 || entry.X is null)
                {
                    break;
                }

                entries.Add(entry);

                // Si on a presque tout consommé, stop (padding éventuel).
                if (payload.Length - offset <= 2)
                {
                    break;
                }
            }
            catch
            {
                offset = entryStart;
                break;
            }

            if (offset <= entryStart)
            {
                break;
            }
        }

        return entries;
    }

    // Point d'entrée : prend le payload brut (après RC4) et retourne les positions trouvées.
    public static List<Entry> ParseAppData(byte[] payload)
    {
        if (payload.Length < 2)
        {
            return new List<Entry>();
        }

        if (payload[1] != PositionOpcode)
        {
            return new List<Entry>();
        }

        // On commence à l'index 1 : gateway byte[0] sauté, zone opcode[1] = début du stream
        return ParsePositionStream(payload, startOffset: 1);
    }

    // Parcourt le stream d'entrées tant qu'on trouve 0x79 comme opcode d'entrée.
    private static List<Entry> ParsePositionStream(byte[] data, int startOffset)
    {
        var entries = new List<Entry>();
        int offset = startOffset;

        while (offset < data.Length && data[offset] == PositionOpcode)
        {
            int entryStart = offset;

            try
            {
                offset++; // saute l'opcode 0x79 de l'entrée

                int transientId = ReadUnsignedInt2bit(data, ref offset);
                Entry entry = ReadPositionUpdateData(data, ref offset, transientId);
                entries.Add(entry);
            }
            catch
            {
                // Si on déborde, on s'arrête proprement — les entrées déjà lues sont valides
                offset = entryStart;
                break;
            }
        }

        return entries;
    }

    // Entier non signé avec longueur encodée sur 2 bits (format h1emu readUnsignedIntWith2bitLengthValue).
    // byte[0] : bits 0-1 = n (nombre de bytes supplémentaires), bits 2-7 = données
    // bytes[1..n] : données supplémentaires (big endian inversé)
    private static int ReadUnsignedInt2bit(byte[] data, ref int offset)
    {
        int firstByte = data[offset];
        int extraBytes = firstByte & 3;

        // Accumulation en uint : avec 3 octets supplémentaires le dernier décalage est de 24 bits,
        // et un octet >= 0x80 déborderait le bit de signe d'un int. Le décalage à droite devenant
        // arithmétique, on obtiendrait un transientId négatif.
        uint value = (uint)firstByte;

        for (int idx = 0; idx < extraBytes; idx++)
        {
            value += (uint)data[offset + idx + 1] << ((idx + 1) * 8);
        }

        offset += extraBytes + 1;
        return (int)(value >> 2);
    }

    // Entier signé avec longueur encodée sur 2 bits (format h1emu readSignedIntWith2bitLengthValue).
    // byte[0] : bit 0 = signe, bits 1-2 = n, bits 3-7 = données
    private static int ReadSignedInt2bit(byte[] data, ref int offset)
    {
        int firstByte = data[offset];
        int sign = firstByte & 1;
        int extraBytes = (firstByte >> 1) & 3;

        // Même contrainte de débordement que ReadUnsignedInt2bit.
        uint value = (uint)firstByte;

        for (int idx = 0; idx < extraBytes; idx++)
        {
            value += (uint)data[offset + idx + 1] << ((idx + 1) * 8);
        }

        offset += extraBytes + 1;

        int result = (int)(value >> 3);
        return sign != 0 ? -result : result;
    }

    // Lit les champs optionnels d'une entrée position selon les flags actifs.
    // L'ordre de lecture doit correspondre exactement à readPositionUpdateData dans shared.ts (h1emu).
    private static Entry ReadPositionUpdateData(byte[] data, ref int offset, int transientId)
    {
        ushort flags = (ushort)(data[offset] | (data[offset + 1] << 8));
        offset += 2;

        // seqTime (4 bytes) + unk3 (1 byte) — on ne s'en sert pas pour la position
        offset += 5;

        float? x = null;
        float? y = null;
        float? z = null;

        // Stance (0x0001)
        if ((flags & 0x0001) != 0)
        {
            ReadUnsignedInt2bit(data, ref offset);
        }

        // Position XYZ (0x0002) — stockée en centimètres, donc /100 pour avoir des mètres
        if ((flags & 0x0002) != 0)
        {
            x = ReadSignedInt2bit(data, ref offset) / 100f;
            y = ReadSignedInt2bit(data, ref offset) / 100f;
            z = ReadSignedInt2bit(data, ref offset) / 100f;
        }

        // Orientation float32 (0x0020)
        if ((flags & 0x0020) != 0)
        {
            offset += 4;
        }

        // Inclinaison avant (0x0040)
        if ((flags & 0x0040) != 0)
        {
            ReadSignedInt2bit(data, ref offset);
        }

        // Inclinaison latérale (0x0080)
        if ((flags & 0x0080) != 0)
        {
            ReadSignedInt2bit(data, ref offset);
        }

        // Changement d'angle (0x0004)
        if ((flags & 0x0004) != 0)
        {
            ReadSignedInt2bit(data, ref offset);
        }

        // Vitesse verticale (0x0008)
        if ((flags & 0x0008) != 0)
        {
            ReadSignedInt2bit(data, ref offset);
        }

        // Vitesse horizontale (0x0010)
        if ((flags & 0x0010) != 0)
        {
            ReadSignedInt2bit(data, ref offset);
        }

        // Champ inconnu — 3 valeurs (0x0100)
        if ((flags & 0x0100) != 0)
        {
            for (int i = 0; i < 3; i++)
            {
                ReadSignedInt2bit(data, ref offset);
            }
        }

        // Rotation brute — 4 valeurs quaternion (0x0200)
        if ((flags & 0x0200) != 0)
        {
            for (int i = 0; i < 4; i++)
            {
                ReadSignedInt2bit(data, ref offset);
            }
        }

        // Direction (0x0400)
        if ((flags & 0x0400) != 0)
        {
            ReadSignedInt2bit(data, ref offset);
        }

        // 0x0800 (RPM moteur) et tout ce qui est >= 0x1000 :
        // dans ROTK ces flags sont présents dans les données mais ne consomment aucun byte.
        // Si on les lisait, l'offset serait décalé et toutes les entrées suivantes seraient fausses.

        return new Entry(transientId, x, y, z, flags);
    }
}
