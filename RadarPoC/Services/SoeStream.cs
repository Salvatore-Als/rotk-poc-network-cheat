namespace RadarPoC.Services;

// Réassemblage SOE + déchiffrement RC4. Port de soeinputstream.ts (h1emu).
public sealed class SoeStream
{
    private const int DataHeaderSize = 4;
    private const int MaxSequence = 0xFFFF;

    private readonly Rc4 rc4;
    private readonly Action<byte[]> onAppData;

    // Paquets reçus mais pas encore traités (en attente d'un fragment manquant, hors ordre, etc.)
    private readonly Dictionary<int, (byte[] payload, bool isFragment)> pendingPackets = new();

    private int nextExpectedSeq = 0;
    private int lastProcessedSeq = -1;
    private int lastAckedSeq = -1;

    // État du fragment en cours de réassemblage
    private bool   fragmentInProgress;
    private int    fragmentTotalSize;
    private byte[] fragmentBuffer = Array.Empty<byte>();
    private int    fragmentFilled;
    private readonly List<int> fragmentSeqs = new();

    public SoeStream(byte[] key, Action<byte[]> onAppData)
    {
        rc4 = new Rc4(key);
        this.onAppData = onAppData;
    }

    public void Write(byte[] body, int seq, bool isFragment)
    {
        // Dupliqué ou déjà traité → on ignore
        if (seq < nextExpectedSeq)
        {
            return;
        }

        pendingPackets[seq] = (body, isFragment);

        // Avance le curseur d'ack pour savoir jusqu'où on peut traiter
        int ack = seq;
        for (int step = 1; step <= MaxSequence; step++)
        {
            int candidate = (lastAckedSeq + step) & MaxSequence;
            if (pendingPackets.ContainsKey(candidate))
            {
                ack = candidate;
            }
            else
            {
                break;
            }
        }

        lastAckedSeq = ack & MaxSequence;
        nextExpectedSeq = (lastAckedSeq + 1) & MaxSequence;

        ProcessAvailableData();
    }

    private void ProcessAvailableData()
    {
        int nextSeq = (lastProcessedSeq + 1) & MaxSequence;

        if (!pendingPackets.TryGetValue(nextSeq, out var entry))
        {
            return;
        }

        List<byte[]> messages;

        if (entry.isFragment)
        {
            messages = ReassembleFragment(nextSeq);
        }
        else
        {
            pendingPackets.Remove(nextSeq);
            lastProcessedSeq = nextSeq;
            messages = SplitChannelPacket(entry.payload);
        }

        foreach (var msg in messages)
        {
            DecryptAndForward(msg);
        }

        // Récursion : traite le suivant si disponible
        if (messages.Count > 0)
        {
            ProcessAvailableData();
        }
    }

    // Réassemble les DataFragment en un seul bloc, puis le découpe en messages.
    private List<byte[]> ReassembleFragment(int firstSeq)
    {
        // Initialise le buffer si c'est le premier fragment du groupe
        if (!fragmentInProgress)
        {
            byte[] firstPayload = pendingPackets[firstSeq].payload;
            fragmentTotalSize = (firstPayload[0] << 24) | (firstPayload[1] << 16)
                              | (firstPayload[2] << 8)  |  firstPayload[3];
            fragmentBuffer = new byte[fragmentTotalSize];
            fragmentFilled = 0;
            fragmentInProgress = true;
            fragmentSeqs.Clear();
        }

        int offset = fragmentSeqs.Count;

        while (true)
        {
            int fragSeq = (firstSeq + offset) & MaxSequence;

            if (!pendingPackets.TryGetValue(fragSeq, out var frag))
            {
                // On n'a pas encore tous les fragments, on attend
                return new List<byte[]>();
            }

            bool isFirstFragment = (fragSeq == firstSeq);
            fragmentSeqs.Add(fragSeq);

            // Le premier fragment a un header de 4 octets (taille totale) à sauter
            byte[] chunk = isFirstFragment
                ? frag.payload[DataHeaderSize..]
                : frag.payload;

            Buffer.BlockCopy(chunk, 0, fragmentBuffer, fragmentFilled, chunk.Length);
            fragmentFilled += chunk.Length;

            if (fragmentFilled >= fragmentTotalSize)
            {
                // Réassemblage terminé
                foreach (int s in fragmentSeqs)
                {
                    pendingPackets.Remove(s);
                }

                lastProcessedSeq = fragmentSeqs[^1];
                fragmentInProgress = false;

                return SplitChannelPacket(fragmentBuffer[..fragmentTotalSize]);
            }

            offset++;
        }
    }

    // Certains paquets SOE encapsulent plusieurs sous-messages (marqués 0x00 0x19 en tête).
    // Cette fonction les sépare. Si pas de header multi-message, retourne tel quel.
    private static List<byte[]> SplitChannelPacket(byte[] data)
    {
        if (data.Length >= 2 && data[0] == 0x00 && data[1] == 0x19)
        {
            var result = new List<byte[]>();
            int offset = 2;

            while (offset < data.Length)
            {
                int msgLen;
                int sizeFieldLen;

                if (data[offset] == 0xFF)
                {
                    if (offset + 2 < data.Length && data[offset + 1] == 0xFF && data[offset + 2] == 0xFF)
                    {
                        msgLen = (data[offset + 3] << 24) | (data[offset + 4] << 16)
                               | (data[offset + 5] << 8)  |  data[offset + 6];
                        sizeFieldLen = 7;
                    }
                    else
                    {
                        msgLen = (data[offset + 1] << 8) | data[offset + 2];
                        sizeFieldLen = 3;
                    }
                }
                else
                {
                    msgLen = data[offset];
                    sizeFieldLen = 1;
                }

                offset += sizeFieldLen;
                result.Add(data[offset..(offset + msgLen)]);
                offset += msgLen;
            }

            return result;
        }

        return new List<byte[]> { data };
    }

    // Déchiffre avec RC4 puis passe au callback.
    // Note : si les deux premiers octets sont 0x00 0x00, on saute le premier byte avant déchiffrement
    // (comportement hérité de h1emu pour certains paquets non-chiffrés en début de session).
    private void DecryptAndForward(byte[] data)
    {
        byte[] decrypted;

        if (data.Length > 1 && data[0] == 0 && data[1] == 0)
        {
            decrypted = rc4.Crypt(data[1..]);
        }
        else
        {
            decrypted = rc4.Crypt(data);
        }

        onAppData(decrypted);
    }
}
