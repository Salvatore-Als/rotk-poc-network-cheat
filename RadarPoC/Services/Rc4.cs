namespace RadarPoC.Services;

// RC4 stream cipher — implémentation identique à h1emu-core (validé byte par byte).
// La clé LoginUdp par défaut est publique dans h1emu et dans le client H1Z1.
// La réponse de login fournit ensuite une clé de session distincte pour le gateway.
// Une instance = une session SOE. L'état (S-box + i/j) persiste entre les appels.
public sealed class Rc4
{
    public static readonly byte[] DefaultKey = Convert.FromBase64String("F70IaxuU8C/w7FPXY1ibXw==");

    private readonly byte[] sbox = new byte[256];
    private int i;
    private int j;

    public Rc4(byte[] key)
    {
        // KSA — Key Scheduling Algorithm
        for (int idx = 0; idx < 256; idx++)
        {
            sbox[idx] = (byte)idx;
        }

        int swap = 0;
        for (int idx = 0; idx < 256; idx++)
        {
            swap = (swap + sbox[idx] + key[idx % key.Length]) & 0xFF;
            (sbox[idx], sbox[swap]) = (sbox[swap], sbox[idx]);
        }
    }

    // Chiffre ou déchiffre (c'est la même opération en RC4 — XOR avec keystream).
    // Modifie le tableau en place sur la plage [offset, offset+length[.
    public void Crypt(byte[] data, int offset, int length)
    {
        for (int k = 0; k < length; k++)
        {
            i = (i + 1) & 0xFF;
            j = (j + sbox[i]) & 0xFF;
            (sbox[i], sbox[j]) = (sbox[j], sbox[i]);
            data[offset + k] ^= sbox[(sbox[i] + sbox[j]) & 0xFF];
        }
    }

    // Surcharge pratique : retourne une nouvelle copie déchiffrée.
    public byte[] Crypt(byte[] data)
    {
        byte[] result = (byte[])data.Clone();
        Crypt(result, 0, result.Length);
        return result;
    }
}
