using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Microsoft.AspNetCore.SignalR;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using RadarPoC.Hubs;
using RadarPoC.Models;

namespace RadarPoC.Services;

// Service qui tourne en fond pendant toute la durée de l'app.
// Il capture le trafic UDP réseau via SharpPcap (kernel-level, pas de perte comme scapy),
// déchiffre la couche SOE, parse les positions et les envoie au front React via SignalR.
public sealed class PacketCaptureService : BackgroundService
{
    private const int CrcLength = 2;

    // SessionRequest SOE : opcode u16 | crcLength u32 | sessionId u32 | udpLength u32 | protocol ASCII terminé par 0x00
    private const int SessionRequestHeaderSize = 14;

    // Mots-clés pour trouver le process H1Z1 automatiquement
    private static readonly string[] ProcessHints = ["h1z1", "daybreak", "soe", "gamex"];
    private static readonly string[] ProcessExclude = ["launcher"];

    private readonly IHubContext<RadarHub> hub;
    private readonly ILogger<PacketCaptureService> log;

    // Un SoeStream par port UDP local — créé au SessionRequest (seul moment où l'état RC4 est connu).
    private readonly Dictionary<int, SoeStream> streams = new();
    private readonly object streamLock = new();
    private readonly Dictionary<int, bool> compressionByPort = new();
    private readonly Dictionary<int, int> crcLengthByPort = new();

    // Clé RC4 par endpoint "ip:port". LoginUdp fournit la clé du gateway, gateway fournit celle de la zone.
    private readonly Dictionary<string, byte[]> keysByEndpoint = new();

    // Stream en attente de clé (SessionRequest vu, clé pas encore reçue).
    private readonly Dictionary<int, PendingSession> pendingSessions = new();

    private readonly record struct PendingSession(string ServerIp, int ServerPort, string Protocol);

    // Joueurs vus récemment (port, tid) → timestamp ms.
    private readonly ConcurrentDictionary<(int Port, int Tid), long> seenPlayers = new();
    private long lastPlayerCountLogMs;

    // Histogramme d'opcodes pour diagnostic (byte[1] et byte[5]).
    private readonly ConcurrentDictionary<string, int> opcodeHist = new();
    private int appDataTotal;

    // Dump de payloads zone déchiffrés, capé par opcode pour limiter l'espace disque.
    private readonly ConcurrentDictionary<string, int> dumpCounts = new();
    private const int MaxSamplesPerOpcode = 200;
    private string? dumpDir;

    // transient_id → (nom, steamId) — alimenté par les paquets spawn.
    private readonly ConcurrentDictionary<uint, SpawnParser.SpawnInfo> playerRegistry = new();

    // character_id (u64) → SpawnInfo — même joueurs, indexés par l'id complet pour les events kill.
    private readonly ConcurrentDictionary<ulong, SpawnParser.SpawnInfo> charIdRegistry = new();

    // Compteur par signature de payload pour filtrer les events damage vs kill.
    private readonly ConcurrentDictionary<string, int> interactionSignatureCounts = new();
    private string? interactionLogPath;

    public PacketCaptureService(IHubContext<RadarHub> hub, ILogger<PacketCaptureService> log)
    {
        this.hub = hub;
        this.log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        log.LogInformation("En attente du process H1Z1/ROTK...");

        int pid = await WaitForH1Z1Process(ct);

        if (ct.IsCancellationRequested)
        {
            return;
        }

        log.LogInformation("Process trouvé (PID {Pid}), démarrage de la capture", pid);

        // On capture sur TOUTES les interfaces physiques actives.
        // "Connexion au réseau local*" (avec astérisque) = adaptateurs virtuels → on les ignore.
        // On garde Wi-Fi, Ethernet, et autres adaptateurs physiques.
        var devices = CaptureDeviceList.Instance
            .OfType<LibPcapLiveDevice>()
            .Where(d =>
            {
                string name = d.Interface.FriendlyName ?? "";
                bool isLoopback = name.Contains("Loopback", StringComparison.OrdinalIgnoreCase);
                bool isVirtual = name.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
                              || name.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase)
                               || name.EndsWith("*");
                return !isLoopback && !isVirtual;
            })
            .ToList();

        if (devices.Count == 0)
        {
            log.LogError("Aucune interface physique trouvée — relance en administrateur.");
            return;
        }

        log.LogInformation("Capture sur {Count} interface(s) : {Names}",
            devices.Count,
            string.Join(", ", devices.Select(d => d.Interface.FriendlyName)));

        foreach (var dev in devices)
        {
            // Gros buffer kernel : un seul paquet perdu désynchronise RC4 définitivement
            // pour le canal concerné. C'est ce que le POC tshark obtient par défaut.
            dev.Open(new DeviceConfiguration
            {
                Mode = DeviceModes.Promiscuous,
                ReadTimeout = 1000,
                Snaplen = 65536,
                BufferSize = 32 * 1024 * 1024,
            });

            dev.Filter = "udp";
            dev.OnPacketArrival += (sender, args) => HandlePacket(args.GetPacket());
            dev.StartCapture();
        }

        dumpDir = Path.Combine(AppContext.BaseDirectory, "dumps",
            DateTime.UtcNow.ToString("yyyy-MM-ddTHH-mm-ss"));
        Directory.CreateDirectory(dumpDir);
        log.LogInformation("Dump zone payloads → {Dir}", dumpDir);

        interactionLogPath = Path.Combine(dumpDir, "interactions.log");
        File.WriteAllText(interactionLogPath, "# timestamp\tport\tsize\tsig6B\tattacker_cid\tvictim_cid\tattacker_name\tvictim_name\thex\n");
        log.LogInformation("Interaction log → {Path}", interactionLogPath);

        log.LogInformation("Capture démarrée. Lance le jeu.");

        // Notifie le front que le process est trouvé et la capture active
        await hub.Clients.All.SendAsync("gameFound", ct);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                Process.GetProcessById(pid);
            }
            catch (ArgumentException)
            {
                log.LogWarning("Process H1Z1 fermé, arrêt de la capture.");
                break;
            }

            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (nowMs - lastPlayerCountLogMs >= 5_000)
            {
                lastPlayerCountLogMs = nowMs;
                long cutoff = nowMs - 30_000;
                int active = 0;
                foreach (var kv in seenPlayers)
                {
                    if (kv.Value >= cutoff)
                    {
                        active++;
                    }
                }

                log.LogInformation(
                    "Joueurs détectés : {Active} actifs (30s) / {Total} uniques session",
                    active, seenPlayers.Count);
                _ = hub.Clients.All.SendAsync("playerCount", new { active, session = seenPlayers.Count });

                int total = Interlocked.Exchange(ref appDataTotal, 0);
                if (total > 0 && opcodeHist.Count > 0)
                {
                    var top = opcodeHist
                        .OrderByDescending(kv => kv.Value)
                        .Take(12)
                        .Select(kv => $"{kv.Key}:{kv.Value}");
                    string histMsg = $"[diag] 5s total={total} | {string.Join(" ", top)}";
                    log.LogInformation("AppData {Msg}", histMsg);
                    _ = hub.Clients.All.SendAsync("diag", histMsg);
                    opcodeHist.Clear();
                }
            }

            await Task.Delay(500, ct).ConfigureAwait(false);
        }

        foreach (var dev in devices)
        {
            dev.StopCapture();
            dev.Close();
        }
    }

    private void HandlePacket(RawCapture raw)
    {
        try
        {
            var parsed = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

            var udp = parsed.Extract<UdpPacket>();
            var ip = parsed.Extract<IPv4Packet>();

            if (udp is null || ip is null)
            {
                return;
            }

            byte[] payload = udp.PayloadData;
            if (payload is null || payload.Length < 4)
            {
                return;
            }

            int opcode = (payload[0] << 8) | payload[1];

            // SessionRequest client→serveur : ouverture d'un canal SOE.
            if (opcode == 0x0001)
            {
                OpenSession(udp.SourcePort, ip.DestinationAddress.ToString(), udp.DestinationPort, payload);
                return;
            }

            // SessionReply serveur→client :
            // opcode(2), sessionId(4), crcSeed(4), crcLength(1),
            // compression(1), encryption(1), udpLength(4), version(4).
            if (opcode == 0x0002 && payload.Length >= 13)
            {
                lock (streamLock)
                {
                    crcLengthByPort[udp.DestinationPort] = payload[10];
                    compressionByPort[udp.DestinationPort] = payload[11] != 0;
                }
                return;
            }

            // Data / DataFragment du serveur → déchiffrement RC4.
            if (opcode != 0x0009 && opcode != 0x000D)
            {
                return;
            }

            lock (streamLock)
            {
                if (!streams.TryGetValue(udp.DestinationPort, out var stream))
                {
                    if (!TryActivatePendingSession(udp.DestinationPort, out stream))
                    {
                        return;
                    }
                }

                bool hasCompressionFlag = compressionByPort.GetValueOrDefault(udp.DestinationPort);
                int sequenceOffset = hasCompressionFlag ? 3 : 2;
                int bodyOffset = sequenceOffset + 2;
                int crcLength = crcLengthByPort.GetValueOrDefault(udp.DestinationPort, CrcLength);

                if (payload.Length - bodyOffset - crcLength <= 0)
                {
                    return;
                }

                int seq = (payload[sequenceOffset] << 8) | payload[sequenceOffset + 1];
                stream.Write(payload[bodyOffset..(payload.Length - crcLength)], seq, opcode == 0x000D);
            }
        }
        catch (Exception ex)
        {
            log.LogDebug("Erreur parsing paquet : {Message}", ex.Message);
        }
    }

    // Ouvre un canal SOE à partir d'un SessionRequest validé.
    private void OpenSession(int localPort, string serverIp, int serverPort, byte[] payload)
    {
        string? protocol = ReadSessionProtocol(payload);
        if (protocol is null)
        {
            return;
        }

        lock (streamLock)
        {
            compressionByPort[localPort] = false;
            crcLengthByPort[localPort] = CrcLength;

            if (protocol.StartsWith("LoginUdp", StringComparison.Ordinal))
            {
                // Clé publique connue — stream immédiat.
                streams[localPort] = new SoeStream(Rc4.DefaultKey, HandleLoginAppData);
                pendingSessions.Remove(localPort);
            }
            else if (protocol.StartsWith("ExternalGateway", StringComparison.Ordinal))
            {
                // Clé pas encore connue — on attend le CharacterLoginReply avant d'activer.
                pendingSessions[localPort] = new PendingSession(serverIp, serverPort, protocol);
                streams.Remove(localPort);

                string endpoint = $"{serverIp}:{serverPort}";
                if (keysByEndpoint.ContainsKey(endpoint))
                {
                    TryActivatePendingSession(localPort, out _);
                }
                else
                {
                    log.LogInformation("[pending] {Endpoint} port local {Port} — en attente clé RC4",
                        endpoint, localPort);
                    _ = hub.Clients.All.SendAsync("diag", $"⏳ {endpoint} en attente clé RC4");
                }
            }
            else
            {
                return;
            }
        }

        log.LogInformation("Session SOE {Protocol} — port local {Port} → {Server}:{ServerPort}",
            protocol, localPort, serverIp, serverPort);

        _ = hub.Clients.All.SendAsync("channelDetected", new
        {
            port = localPort,
            protocol,
            serverIp,
            serverPort
        });
    }

    // Active un stream pending si la clé endpoint est connue. Appelé sous streamLock.
    private bool TryActivatePendingSession(int localPort, out SoeStream stream)
    {
        stream = null!;
        if (!pendingSessions.TryGetValue(localPort, out var pending))
        {
            return false;
        }

        string endpoint = $"{pending.ServerIp}:{pending.ServerPort}";
        if (!keysByEndpoint.TryGetValue(endpoint, out byte[]? key))
        {
            log.LogWarning("[ZONE/GW {Endpoint}] Data reçu sans clé RC4 — drop. " +
                           "Handoff introuvable : gateway ou lobby zone n'a pas exposé la clé. " +
                           "Relance capture AVANT lobby, ou augmente MaxSamplesPerOpcode.",
                           endpoint);
            return false;
        }

        Action<byte[]> callback;
        if (pending.ServerPort == 20145)
        {
            callback = HandleGatewayAppData;
        }
        else
        {
            callback = data => HandleAppData(localPort, data);
        }

        stream = new SoeStream(key, callback);
        streams[localPort] = stream;
        pendingSessions.Remove(localPort);

        log.LogInformation("[OK] {Endpoint} port local {Port} — clé RC4 activée ({Key})",
            endpoint, localPort, Convert.ToBase64String(key));
        _ = hub.Clients.All.SendAsync("diag",
            $"✓ {endpoint} clé RC4 : {Convert.ToBase64String(key)}");

        // Nouvelle zone activée → purge les positions de l'ancienne zone côté front.
        if (callback.Method.Name != nameof(HandleGatewayAppData))
        {
            _ = hub.Clients.All.SendAsync("clearPlayers");
        }

        return true;
    }

    // Lit le nom de protocole d'un SessionRequest, ou null si le paquet n'est pas un
    // SessionRequest SOE. Sert de validation structurelle : sans elle, n'importe quel
    // datagramme UDP commençant par 0x00 0x01 ouvrirait un canal.
    private static string? ReadSessionProtocol(byte[] payload)
    {
        if (payload.Length <= SessionRequestHeaderSize)
        {
            return null;
        }

        int end = Array.IndexOf(payload, (byte)0, SessionRequestHeaderSize);
        if (end <= SessionRequestHeaderSize)
        {
            return null;
        }

        for (int i = SessionRequestHeaderSize; i < end; i++)
        {
            if (payload[i] < 0x20 || payload[i] > 0x7E)
            {
                return null;
            }
        }

        return Encoding.ASCII.GetString(payload, SessionRequestHeaderSize, end - SessionRequestHeaderSize);
    }

    // CharacterLoginReply / redirect zone : address + ticket + encryption_key(16).
    // Même struct sur LoginUdp, gateway et handoff zone→zone.
    private void HandleLoginAppData(byte[] payload)
    {
        ExtractAndStoreSessionKeys(payload, "LoginUdp");
        DumpLoginSample(payload);
    }

    // Dump login-session payloads. Zone key handoffs may travel here rather than
    // through the gateway → without this we miss the BR zone key silently.
    private void DumpLoginSample(byte[] payload)
    {
        if (dumpDir is null || payload.Length < 2)
        {
            return;
        }

        string tag = payload.Length >= 6
            ? $"login_op{payload[5]:X2}"
            : $"login_short{payload[0]:X2}";

        int count = dumpCounts.AddOrUpdate(tag, 1, (_, v) => v + 1);
        if (count > MaxSamplesPerOpcode)
        {
            return;
        }

        try
        {
            string opDir = Path.Combine(dumpDir, tag);
            Directory.CreateDirectory(opDir);
            string fileName = $"login_{count:D4}.bin";
            File.WriteAllBytes(Path.Combine(opDir, fileName), payload);
        }
        catch (Exception ex)
        {
            log.LogDebug("Login dump write failed for {Tag}: {Message}", tag, ex.Message);
        }
    }

    private void HandleGatewayAppData(byte[] payload)
    {
        ExtractAndStoreSessionKeys(payload, "gateway");
        DumpGatewaySample(payload);
    }

    // Gateway payloads carry zone key handoffs. Dump every unique first-6-byte signature
    // so we can offline-recover missing zone keys.
    private void DumpGatewaySample(byte[] payload)
    {
        if (dumpDir is null || payload.Length < 2)
        {
            return;
        }

        string tag = payload.Length >= 6
            ? $"gateway_op{payload[5]:X2}"
            : $"gateway_short{payload[0]:X2}";

        int count = dumpCounts.AddOrUpdate(tag, 1, (_, v) => v + 1);
        if (count > MaxSamplesPerOpcode)
        {
            return;
        }

        try
        {
            string opDir = Path.Combine(dumpDir, tag);
            Directory.CreateDirectory(opDir);
            string fileName = $"gw_{count:D4}.bin";
            File.WriteAllBytes(Path.Combine(opDir, fileName), payload);
        }
        catch (Exception ex)
        {
            log.LogDebug("Gateway dump write failed for {Tag}: {Message}", tag, ex.Message);
        }
    }

    private void ExtractAndStoreSessionKeys(byte[] payload, string source)
    {
        for (int offset = 0; offset <= payload.Length - 12; offset++)
        {
            int addressLength = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(offset, 4));
            if (addressLength is < 7 or > 80 || offset + 4 + addressLength + 8 > payload.Length)
            {
                continue;
            }

            ReadOnlySpan<byte> addressBytes = payload.AsSpan(offset + 4, addressLength);
            if (!addressBytes.Contains((byte)':'))
            {
                continue;
            }

            bool validAddress = true;
            foreach (byte value in addressBytes)
            {
                if (value is < 0x20 or > 0x7E)
                {
                    validAddress = false;
                    break;
                }
            }

            if (!validAddress)
            {
                continue;
            }

            string address = Encoding.ASCII.GetString(addressBytes);
            // host:port strict (évite les faux positifs type "LIVE_KOTK:foo")
            int colon = address.LastIndexOf(':');
            if (colon <= 0 || colon >= address.Length - 1
                || !int.TryParse(address.AsSpan(colon + 1), out int port)
                || port is < 1 or > 65535)
            {
                continue;
            }

            int ticketLengthOffset = offset + 4 + addressLength;
            int ticketLength = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(ticketLengthOffset, 4));
            int keyLengthOffset = ticketLengthOffset + 4 + ticketLength;

            if (ticketLength is < 8 or > 512 || keyLengthOffset + 4 > payload.Length)
            {
                continue;
            }

            int keyLength = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(keyLengthOffset, 4));
            if (keyLength != 16 || keyLengthOffset + 4 + keyLength > payload.Length)
            {
                continue;
            }

            byte[] key = payload[(keyLengthOffset + 4)..(keyLengthOffset + 4 + keyLength)];

            lock (streamLock)
            {
                bool isNew = !keysByEndpoint.ContainsKey(address);
                keysByEndpoint[address] = key;

                if (isNew)
                {
                    log.LogInformation("Clé RC4 [{Source}] {Endpoint} = {Key}",
                        source, address, Convert.ToBase64String(key));
                    _ = hub.Clients.All.SendAsync("diag",
                        $"✓ Clé [{source}] {address} = {Convert.ToBase64String(key)}");
                }

                // Active les sessions pending qui attendaient exactement cet endpoint.
                foreach (var kv in pendingSessions.ToList())
                {
                    string ep = $"{kv.Value.ServerIp}:{kv.Value.ServerPort}";
                    if (ep == address)
                    {
                        TryActivatePendingSession(kv.Key, out _);
                    }
                }
            }

            // Un message peut contenir plusieurs redirects — on continue le scan.
        }
    }

    // Reçoit un message applicatif déchiffré zone : keys de handoff + positions.
    private void HandleAppData(int port, byte[] payload)
    {
        // Handoff lobby→BR : la zone courante envoie addr+ticket+key de la suivante.
        ExtractAndStoreSessionKeys(payload, $"zone:{port}");

        DumpZoneSample(port, payload);

        // Spawn/profile packets carry (transient_id, name, steamId) — populate registry
        // so position updates can be attributed to real player names.
        var spawn = SpawnParser.TryParse(payload);
        if (spawn is not null)
        {
            var info = spawn.Value;
            if (playerRegistry.TryAdd(info.TransientId, info))
            {
                charIdRegistry.TryAdd(info.CharacterId, info);

                log.LogInformation("[spawn] cid=0x{Cid:X16} tid=0x{Tid:X8} → {Name} (steam {SteamId})",
                    info.CharacterId, info.TransientId, info.Name, info.SteamId);
                _ = hub.Clients.All.SendAsync("playerRegistered", new
                {
                    transientId = info.TransientId,
                    characterId = info.CharacterId.ToString(),
                    name = info.Name,
                    steamId = info.SteamId,
                });
            }
        }

        if (!TryParseKillBroadcast(port, payload))
        {
            DetectKillEvent(port, payload);
        }

        Interlocked.Increment(ref appDataTotal);

        // Histogramme diagnostic : on track le gateway byte, zone_op byte[1] et byte[5] (tunnel).
        if (payload.Length >= 2)
        {
            string key1 = $"gw={payload[0]:X2}/op1={payload[1]:X2}";
            opcodeHist.AddOrUpdate(key1, 1, (_, v) => v + 1);
        }
        if (payload.Length >= 6)
        {
            // Format tunnel TunneledClientPacketV1 : byte[0]=(ch<<5)|0x05, byte[1..4]=length, byte[5]=zone opcode
            bool isTunnel = (payload[0] & 0x1F) == 0x05;
            if (isTunnel)
            {
                string key5 = $"tunnel/op5={payload[5]:X2}";
                opcodeHist.AddOrUpdate(key5, 1, (_, v) => v + 1);
            }
        }

        // Opcode 0x06 : potentiellement ChatText / killfeed
        if (payload.Length >= 3 && payload[1] == 0x06)
        {
            // Hex brut des 80 premiers octets pour reverse le format
            string hex = BitConverter.ToString(payload[..Math.Min(80, payload.Length)]).Replace("-", " ");

            // Scan ASCII (noms ASCII pur)
            var ascii = ExtractAsciiStrings(payload, startOffset: 2, minLen: 4);

            // Scan UTF-16 LE (noms souvent stockés en wide char)
            var utf16 = ExtractUtf16Strings(payload, startOffset: 2, minLen: 3);

            var allStr = ascii.Concat(utf16).Distinct().ToList();
            string strPart;
            if (allStr.Count > 0)
            {
                strPart = string.Join(" | ", allStr);
            }
            else
            {
                strPart = "(no strings)";
            }

            string msg = $"[port {port}] [0x06] sub=0x{payload[2]:X2} len={payload.Length} | {strPart}\n  HEX: {hex}";
            log.LogInformation(msg);
            _ = hub.Clients.All.SendAsync("diag", msg);
        }

        List<PositionParser.Entry> entries;
        int parseOffset = -1;

        // opAE : format variable-length (marker 22 03 78), priorité haute.
        if (PositionParser.ParsePositionOpAE(payload) is { } posAE)
        {
            entries = new List<PositionParser.Entry> { posAE };
            parseOffset = payload.Length;
        }
        // Zone opcode 0x79 après le gateway byte.
        else if (payload.Length >= 2 && payload[1] == 0x79)
        {
            entries = PositionParser.ParseFromOffset(payload, 1);
            parseOffset = 1;
        }
        // Tunnel TunneledClientPacketV1 : opcode à byte[5].
        else if (payload.Length >= 6 && (payload[0] & 0x1F) == 0x05 && payload[5] == 0x79)
        {
            entries = PositionParser.ParseFromOffset(payload, 5);
            parseOffset = 5;
        }
        // Opcode 0x79 en tête directe (pas de gateway byte).
        else if (payload.Length >= 1 && payload[0] == 0x79)
        {
            entries = PositionParser.ParseFromOffset(payload, 0);
            parseOffset = 0;
        }
        // Channel 2 raw — exige flag position 0x2.
        else if (payload.Length >= 10 && (payload[0] & 0xE0) == 0x40)
        {
            entries = PositionParser.ParseDirectStream(payload, startOffset: 1);
            parseOffset = 0;
        }
        else
        {
            return;
        }

        if (entries.Count == 0)
        {
            return;
        }

        var valid = new List<PositionParser.Entry>();
        int skipped = 0;
        int noXYZ = 0;

        foreach (var entry in entries)
        {
            if (entry.X is null || entry.Y is null || entry.Z is null)
            {
                noXYZ++;
                continue;
            }

            // Bornes map KotK (~6144) — hors-bornes = parse faux, pas un joueur lointain.
            if (entry.X < -500 || entry.X > 7000
             || entry.Y < -200 || entry.Y > 1000
             || entry.Z < -500 || entry.Z > 7000)
            {
                skipped++;
                continue;
            }

            // tid 0 / négatif = garbage uint2bit
            if (entry.TransientId <= 0)
            {
                skipped++;
                continue;
            }

            valid.Add(entry);
        }

        if (skipped > 0)
        {
            opcodeHist.AddOrUpdate($"off={parseOffset}/hors-bornes", skipped, (_, v) => v + skipped);
        }

        if (noXYZ > 0)
        {
            opcodeHist.AddOrUpdate($"off={parseOffset}/noXYZ", noXYZ, (_, v) => v + noXYZ);
        }

        if (valid.Count == 0)
        {
            return;
        }

        opcodeHist.AddOrUpdate($"off={parseOffset}/ok", valid.Count, (_, v) => v + valid.Count);

        var positions = new List<PlayerPosition>();

        long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        foreach (var entry in valid)
        {
            seenPlayers[(port, entry.TransientId)] = nowMs;

            playerRegistry.TryGetValue((uint)entry.TransientId, out var info);

            positions.Add(new PlayerPosition
            {
                TransientId = entry.TransientId,
                X = entry.X!.Value,
                Y = entry.Y!.Value,
                Z = entry.Z!.Value,
                Port = port,
                Timestamp = nowMs,
                Name = info.Name,
                SteamId = info.SteamId,
            });
        }

        // Un seul log agrégé par paquet (évite de noyer le front).
        if (valid.Count > 0)
        {
            var sample = valid[0];
            log.LogInformation(
                "[port {Port}] off={Off} +{Count} joueurs (ex tid={Tid} {X:F0},{Y:F0},{Z:F0})",
                port, parseOffset, valid.Count, sample.TransientId, sample.X, sample.Y, sample.Z);
        }

        _ = hub.Clients.All.SendAsync("positions", positions);
    }

    // BR kill broadcast: zone opcode 0x02, ~240-260B.
    // Structure: tunnel header (9B) | victim_char_id u64 LE | victim_steam u64 | zeros(4) |
    //            victim_name_len u32 | victim_name | null_pad(4) | steam_str_len u32 | steam_str(17) |
    //            zeros(13) | rank u32 | unk(4) | unk(4) | unk(4) | kill_type u32 |
    //            attacker_char_id u64 LE | ... | att_name_len u32 | att_name | ...
    // kill_type: 4 = normal, 5 = headshot.
    // Attacker block starts at fixed offset 91 + victim_name_len.
    private bool TryParseKillBroadcast(int port, byte[] p)
    {
        // Signature: tunnel (byte[0]&0x1F==0x05), zone opcode byte[5]==0x02, large packet.
        if (p.Length < 120 || (p[0] & 0x1F) != 0x05 || p[5] != 0x02)
        {
            return false;
        }

        try
        {
            // Victim name at offset 33, length at offset 29.
            int vicNlen = BinaryPrimitives.ReadInt32LittleEndian(p.AsSpan(29, 4));
            if (vicNlen is < 1 or > 60 || 33 + vicNlen > p.Length)
            {
                return false;
            }

            // Validate victim name is printable ASCII.
            for (int i = 33; i < 33 + vicNlen; i++)
            {
                if (p[i] < 0x20 || p[i] > 0x7E)
                {
                    return false;
                }
            }

            string vicName = Encoding.ASCII.GetString(p, 33, vicNlen);

            // Attacker block at 91 + vicNlen.
            int attOff = 91 + vicNlen;
            if (attOff + 24 > p.Length)
            {
                return false;
            }

            int attNlenOff = attOff + 20;
            int attNlen = BinaryPrimitives.ReadInt32LittleEndian(p.AsSpan(attNlenOff, 4));
            if (attNlen is < 1 or > 60 || attNlenOff + 4 + attNlen > p.Length)
            {
                return false;
            }

            for (int i = attNlenOff + 4; i < attNlenOff + 4 + attNlen; i++)
            {
                if (p[i] < 0x20 || p[i] > 0x7E)
                {
                    return false;
                }
            }

            string attName = Encoding.ASCII.GetString(p, attNlenOff + 4, attNlen);

            // kill_type at offset 91+vicNlen-4 (last u32 of victim stats block).
            // 4=normal, 5=headshot.
            int killTypeOff = attOff - 4;
            bool headshot = killTypeOff >= 0
                && BinaryPrimitives.ReadInt32LittleEndian(p.AsSpan(killTypeOff, 4)) == 5;

            string hs = headshot ? " [HEADSHOT]" : "";
            log.LogInformation("☠ {Att} KILLED {Vic}{HS} (port {Port})", attName, vicName, hs, port);

            _ = hub.Clients.All.SendAsync("killEvent", new
            {
                port,
                killer = attName,
                victim = vicName,
                headshot,
            });

            return true;
        }
        catch
        {
            return false;
        }
    }

    // Fallback heuristic for lobby/unknown formats: scan for 2+ registered char_ids.
    // Logs to interactions.log for offline signature analysis.
    private void DetectKillEvent(int port, byte[] payload)
    {
        if (payload.Length < 24 || payload.Length > 200 || charIdRegistry.IsEmpty)
        {
            return;
        }

        var matched = new List<(int offset, SpawnParser.SpawnInfo info)>();
        for (int off = 0; off + 8 <= payload.Length; off++)
        {
            ulong candidate = BinaryPrimitives.ReadUInt64LittleEndian(payload.AsSpan(off, 8));
            if (charIdRegistry.TryGetValue(candidate, out var info))
            {
                matched.Add((off, info));
            }
        }

        if (matched.Count < 2)
        {
            return;
        }

        if (payload.Length == 25 && payload[0] == 0x45)
        {
            return;
        }

        var attacker = matched[0].info;
        var victim = matched[1].info;
        if (attacker.CharacterId == victim.CharacterId)
        {
            return;
        }

        string sig6 = Convert.ToHexString(payload[..Math.Min(6, payload.Length)]);
        string sigKey = $"{sig6}_len{payload.Length}";
        int count = interactionSignatureCounts.AddOrUpdate(sigKey, 1, (_, v) => v + 1);
        string hex = Convert.ToHexString(payload[..Math.Min(80, payload.Length)]);

        if (interactionLogPath is not null)
        {
            try
            {
                string line = string.Join('\t',
                    DateTimeOffset.UtcNow.ToString("HH:mm:ss.fff"),
                    port.ToString(),
                    payload.Length.ToString(),
                    sigKey,
                    attacker.CharacterId.ToString("X16"),
                    victim.CharacterId.ToString("X16"),
                    attacker.Name,
                    victim.Name,
                    hex) + "\n";
                File.AppendAllText(interactionLogPath, line);
            }
            catch { /* best effort */ }
        }

        if (count >= 3)
        {
            return;
        }

        log.LogInformation("[kill?] port={Port} sig={Sig} count={Count} atk={Atk} vic={Vic}",
            port, sigKey, count, attacker.Name, victim.Name);

        _ = hub.Clients.All.SendAsync("killEvent", new
        {
            port,
            killer = attacker.Name,
            killerId = attacker.CharacterId.ToString(),
            victim = victim.Name,
            victimId = victim.CharacterId.ToString(),
            payloadLen = payload.Length,
            signature = sigKey,
            hex,
        });
    }

    // Sample decrypted zone payloads per opcode signature. Cap keeps disk tiny.
    // Files: dumps/<session>/<tag>/port<PORT>_<NNN>.bin  (raw payload after RC4).
    private void DumpZoneSample(int port, byte[] payload)
    {
        if (dumpDir is null || payload.Length < 2)
        {
            return;
        }

        string tag;
        if (payload.Length >= 6 && (payload[0] & 0x1F) == 0x05)
        {
            tag = $"tunnel_op{payload[5]:X2}";
        }
        else if ((payload[0] & 0xE0) == 0x40 && payload.Length >= 3)
        {
            tag = $"ch2_gw{payload[0]:X2}";
        }
        else
        {
            tag = $"raw_op{payload[1]:X2}";
        }

        int count = dumpCounts.AddOrUpdate(tag, 1, (_, v) => v + 1);
        if (count > MaxSamplesPerOpcode)
        {
            return;
        }

        try
        {
            string opDir = Path.Combine(dumpDir, tag);
            Directory.CreateDirectory(opDir);
            string fileName = $"port{port}_{count:D3}.bin";
            File.WriteAllBytes(Path.Combine(opDir, fileName), payload);
        }
        catch (Exception ex)
        {
            log.LogDebug("Dump write failed for {Tag}: {Message}", tag, ex.Message);
        }
    }

    // Boucle jusqu'à trouver un process qui ressemble à H1Z1.
    // On attend qu'il soit lancé si nécessaire.
    private async Task<int> WaitForH1Z1Process(CancellationToken ct)
    {
        bool firstPass = true;

        while (!ct.IsCancellationRequested)
        {
            var allNames = new List<string>();

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    allNames.Add(name);

                    bool matchesHint = ProcessHints.Any(hint => name.Contains(hint));
                    bool matchesExclude = ProcessExclude.Any(ex => name.Contains(ex));

                    if (matchesHint && !matchesExclude)
                    {
                        log.LogInformation("Process trouvé : {Name} (PID {Pid})", proc.ProcessName, proc.Id);
                        return proc.Id;
                    }
                }
                catch
                {
                    // Process inaccessible, on skip
                }
            }

            // Premier passage : affiche tous les process pour débugger
            if (firstPass)
            {
                log.LogInformation("Process en cours : {List}", string.Join(", ", allNames.Distinct().OrderBy(n => n).Take(40)));
                firstPass = false;
            }

            await Task.Delay(500, ct).ConfigureAwait(false);
        }

        return -1;
    }

    // Extrait les strings UTF-16 LE (wide char) — noms de joueurs souvent encodés ainsi.
    private static List<string> ExtractUtf16Strings(byte[] data, int startOffset, int minLen)
    {
        var result = new List<string>();
        int i = startOffset;

        while (i + 1 < data.Length)
        {
            // Détecte séquence UTF-16 LE : byte impair = 0x00, byte pair = ASCII printable
            if (data[i] >= 0x20 && data[i] <= 0x7E && i + 1 < data.Length && data[i + 1] == 0x00)
            {
                int start = i;
                while (i + 1 < data.Length && data[i] >= 0x20 && data[i] <= 0x7E && data[i + 1] == 0x00)
                    i += 2;
                int charCount = (i - start) / 2;
                if (charCount >= minLen)
                {
                    var sb = new System.Text.StringBuilder(charCount);
                    for (int j = 0; j < charCount; j++)
                        sb.Append((char)data[start + j * 2]);
                    result.Add($"[u16]{sb}");
                }
                continue;
            }
            i++;
        }

        return result;
    }

    // Extrait les séquences ASCII lisibles d'un payload (pour détecter du texte dans 0x06 / killfeed).
    private static List<string> ExtractAsciiStrings(byte[] data, int startOffset, int minLen)
    {
        var result = new List<string>();
        int i = startOffset;

        while (i < data.Length)
        {
            // Tentative lecture length-prefixed string (uint16 LE puis uint32 LE)
            foreach (int lenSize in new[] { 2, 4 })
            {
                if (i + lenSize >= data.Length)
                    continue;

                int strLen = lenSize == 2
                    ? data[i] | (data[i + 1] << 8)
                    : data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);

                if (strLen >= minLen && strLen <= 256 && i + lenSize + strLen <= data.Length)
                {
                    bool allPrint = true;
                    for (int j = 0; j < strLen; j++)
                    {
                        byte b = data[i + lenSize + j];
                        if (b < 0x20 || b > 0x7E) { allPrint = false; break; }
                    }
                    if (allPrint)
                    {
                        result.Add(Encoding.ASCII.GetString(data, i + lenSize, strLen));
                        i += lenSize + strLen;
                        goto nextByte;
                    }
                }
            }

            // Scan brut : séquence de bytes ASCII consécutifs
            if (data[i] >= 0x20 && data[i] <= 0x7E)
            {
                int start = i;
                while (i < data.Length && data[i] >= 0x20 && data[i] <= 0x7E)
                    i++;
                if (i - start >= minLen)
                    result.Add(Encoding.ASCII.GetString(data, start, i - start));
                continue;
            }

            i++;
            nextByte:;
        }

        return result;
    }
}
