using System.Buffers.Binary;
using System.Text;

namespace RadarPoC.Services;

// Parse les paquets spawn ROTK pour extraire (transient_id, nom, Steam ID).
//
// Format (0x05 tunnel) :
//   [0]     0x05           gateway byte
//   [1..N]  header variable selon flags (0xc2 → transient à [2..5], 0x71 0x03 → [3..6])
//   [X..]   u32 LE name_len + name (ASCII)
//   [Y..]   4 zero bytes + u32 LE=17 + Steam ID (17 digits, préfixe "7656119")
//
// On scanne le pattern Steam ID ancré par son préfixe, puis on remonte pour le nom.
public static class SpawnParser
{
    // TransientId = 32 bits bas du CharacterId (u64).
    public readonly record struct SpawnInfo(uint TransientId, ulong CharacterId, string Name, string SteamId);

    // Steam IDs are always 17 digits and start with "7656119" for real accounts.
    private static readonly byte[] SteamIdPrefix = Encoding.ASCII.GetBytes("7656119");

    // ~17-char steam id prefixed by u32(17) — pattern anchors reverse parse.
    private const int SteamIdLength = 17;

    public static SpawnInfo? TryParse(byte[] payload)
    {
        if (payload.Length < 40 || payload[0] != 0x05)
        {
            return null;
        }

        // Find "7656119" preceded by 0x11 0x00 0x00 0x00 (u32 LE = 17).
        int steamStart = FindSteamId(payload);
        if (steamStart < 0)
        {
            return null;
        }

        // Steam ID starts here; length prefix = 4 bytes before.
        // Read name from the length-prefixed field earlier in the packet.
        // Walk backwards: after name comes 4 zero bytes then the "17" length prefix.
        int nameZeroBoundary = steamStart - 4; // start of "17 00 00 00"

        // Search backward for a u32 LE in [1..31] range immediately followed by ASCII name.
        int nameLenOffset = -1;
        int nameLen = 0;
        for (int i = nameZeroBoundary - 5; i >= 4; i--)
        {
            int candLen = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(i, 4));
            if (candLen < 1 || candLen > 31)
            {
                continue;
            }

            int nameEnd = i + 4 + candLen;
            if (nameEnd > nameZeroBoundary)
            {
                continue;
            }

            // All name bytes must be printable ASCII.
            bool valid = true;
            for (int j = i + 4; j < nameEnd; j++)
            {
                byte b = payload[j];
                if (b < 0x20 || b > 0x7e)
                {
                    valid = false;
                    break;
                }
            }

            // Bytes between end-of-name and the "17" length prefix must be zero pad.
            if (valid)
            {
                for (int j = nameEnd; j < nameZeroBoundary; j++)
                {
                    if (payload[j] != 0)
                    {
                        valid = false;
                        break;
                    }
                }
            }

            if (valid)
            {
                nameLenOffset = i;
                nameLen = candLen;
                break;
            }
        }

        if (nameLenOffset < 0)
        {
            return null;
        }

        string name = Encoding.ASCII.GetString(payload, nameLenOffset + 4, nameLen);
        string steamId = Encoding.ASCII.GetString(payload, steamStart, SteamIdLength);

        // Extract full character u64 from packet header (bytes[2..9] for c2 header,
        // bytes[3..10] for 71 03 header). TransientId = lower 32 bits.
        ulong characterId;
        if (payload[1] == 0xc2 && payload.Length >= 10)
        {
            characterId = BinaryPrimitives.ReadUInt64LittleEndian(payload.AsSpan(2, 8));
        }
        else if (payload[1] == 0x71 && payload[2] == 0x03 && payload.Length >= 11)
        {
            characterId = BinaryPrimitives.ReadUInt64LittleEndian(payload.AsSpan(3, 8));
        }
        else
        {
            return null;
        }

        uint transient = (uint)(characterId & 0xFFFFFFFF);

        return new SpawnInfo(transient, characterId, name, steamId);
    }

    private static int FindSteamId(byte[] payload)
    {
        // Look for "7656119" preceded by (0x11, 0x00, 0x00, 0x00) length prefix.
        for (int i = 4; i <= payload.Length - SteamIdLength; i++)
        {
            if (payload[i - 4] != 0x11 || payload[i - 3] != 0
             || payload[i - 2] != 0    || payload[i - 1] != 0)
            {
                continue;
            }

            bool match = true;
            for (int k = 0; k < SteamIdPrefix.Length; k++)
            {
                if (payload[i + k] != SteamIdPrefix[k])
                {
                    match = false;
                    break;
                }
            }
            if (!match)
            {
                continue;
            }

            // Remaining 10 bytes must be ASCII digits.
            for (int k = SteamIdPrefix.Length; k < SteamIdLength; k++)
            {
                byte b = payload[i + k];
                if (b < (byte)'0' || b > (byte)'9')
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return i;
            }
        }

        return -1;
    }
}
