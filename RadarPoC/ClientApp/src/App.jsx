import { useEffect, useState, useRef } from "react";
import * as signalR from "@microsoft/signalr";
import Radar from "./components/Radar";
import StatusBadge from "./components/StatusBadge";
import PlayerPanel from "./components/PlayerPanel";
import ChannelPanel from "./components/ChannelPanel";
import LogPanel from "./components/LogPanel";
import { portColor } from "./utils/portColor";

const HUB_URL = "http://localhost:5000/hub/radar";

export default function App() {
  const [players, setPlayers] = useState({});
  const [statusKey, setStatus] = useState("CONNECTING");
  // Affichage tronqué ; fullLogRef garde TOUT pour Copier / .log
  const [logs, setLogs] = useState(["[boot] RadarPoC démarré, connexion SignalR..."]);
  const [logTotal, setLogTotal] = useState(1);
  const [channels, setChannels] = useState({});
  const [sessionCount, setSessionCount] = useState(0);
  const [kills, setKills] = useState([]);
  const fullLogRef = useRef(["[boot] RadarPoC démarré, connexion SignalR..."]);

  function addLog(msg) {
    const line = `[${new Date().toLocaleTimeString()}] ${msg}`;
    fullLogRef.current.push(line);
    setLogTotal(fullLogRef.current.length);
    // UI : 200 dernières (ordre inverse, plus récent en tête)
    setLogs(prev => [line, ...prev].slice(0, 200));
  }

  function copyLogs() {
    const text = fullLogRef.current.join("\n");
    navigator.clipboard.writeText(text).then(
      () => addLog(`Logs copiés (${fullLogRef.current.length} lignes).`),
      () => addLog("Échec copie clipboard.")
    );
  }

  function downloadLogs() {
    const text = fullLogRef.current.join("\n");
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `radar-poc-${new Date().toISOString().replace(/[:.]/g, "-")}.log`;
    a.click();
    URL.revokeObjectURL(url);
    addLog(`Logs téléchargés (${fullLogRef.current.length} lignes).`);
  }

  useEffect(() => {
    const conn = new signalR.HubConnectionBuilder()
      .withUrl(HUB_URL)
      .withAutomaticReconnect()
      .configureLogging(signalR.LogLevel.Warning)
      .build();

    conn.onreconnecting(() => {
      setStatus("CONNECTING");
      addLog("SignalR — tentative de reconnexion...");
    });

    conn.onreconnected(() => {
      setStatus("CONNECTED");
      addLog("SignalR reconnecté.");
    });

    conn.onclose(() => {
      setStatus("DISCONNECTED");
      addLog("Connexion SignalR perdue.");
    });

    conn.on("connected", ({ message }) => {
      setStatus("CONNECTED");
      addLog(message);
      addLog("Lance H1Z1 — détection du process automatique.");
    });

    conn.on("gameFound", () => {
      setStatus("GAME_FOUND");
      addLog("Process H1Z1 trouvé — capture UDP démarrée.");
    });

    conn.on("channelDetected", channel => {
      setChannels(prev => ({ ...prev, [channel.port]: channel }));
      addLog(
        `Canal :${channel.port} ${channel.protocol} → ` +
        `${channel.serverIp}:${channel.serverPort}`
      );
    });

    conn.on("clearPlayers", () => {
      setPlayers({});
      addLog("Nouvelle zone — positions purgées.");
    });

    conn.on("diag", msg => addLog(msg));
    conn.on("playerCount", ({ active, session }) => {
      setSessionCount(session);
      addLog(`Joueurs : ${active} actifs (30s) / ${session} uniques session`);
    });

    conn.on("positions", list => {
      const receivedAt = Date.now();
      setPlayers(prev => {
        const next = { ...prev };
        list.forEach(p => {
          next[`${p.port}:${p.transientId}`] = { ...p, receivedAt };
        });
        return next;
      });
      // Pas de log par position — trop de spam.
    });

    conn.on("killEvent", ev => {
      const hs = ev.headshot ? " [HEADSHOT]" : "";
      addLog(`☠ ${ev.killer} → ${ev.victim}${hs}`);
      setKills(prev => [{ ...ev, at: Date.now() }, ...prev.slice(0, 49)]);
    });

    conn.start()
      .then(() => addLog("SignalR connecté."))
      .catch(() => {
        setStatus("DISCONNECTED");
        addLog("Impossible de joindre le serveur — dotnet run lancé ?");
      });

    // Horodatage local (receivedAt) : le timestamp serveur peut manquer selon la
    // sérialisation SignalR, et vidait alors toute la liste à chaque tick.
    const cleanup = setInterval(() => {
      const oldest = Date.now() - 300_000; // 5 minutes
      setPlayers(prev => Object.fromEntries(
        Object.entries(prev).filter(([, p]) => (p.receivedAt ?? 0) >= oldest)
      ));
    }, 5_000);

    return () => {
      clearInterval(cleanup);
      conn.stop();
    };
  }, []);

  return (
    <div className="flex flex-wrap gap-10 p-10">

      {/* ── Colonne gauche : radar ── */}
      <div className="w-full max-w-[624px]">
        <div className="mb-6">
          <div className="flex items-baseline gap-3 mb-2">
            <span className="text-4xl font-bold text-signal tracking-wider" style={{ fontFamily: '"Eurostile", "Arial Narrow", Arial, sans-serif' }}>
              ROTK
            </span>
            <span className="text-4xl font-bold text-paper tracking-wider" style={{ fontFamily: '"Eurostile", "Arial Narrow", Arial, sans-serif' }}>
              RADAR
            </span>
            <span className="text-base text-muted ml-1 self-end mb-1">PoC</span>
          </div>
          <div className="text-xs text-muted font-mono tracking-wide">
            RC4 · F70IaxuU8C/w7FPXY1ibXw==
          </div>
        </div>

        <StatusBadge statusKey={statusKey} />
        <Radar players={players} />

        {/* Légende par canal */}
        <div className="mt-3 text-[11px] text-muted flex gap-4 flex-wrap">
          {Object.values(channels).map(channel => (
            <span key={channel.port} className="flex items-center gap-1.5">
              <span style={{ color: portColor(channel.port) }}>●</span>
              <span>:{channel.port}</span>
            </span>
          ))}
        </div>
      </div>

      {/* ── Colonne droite : stats + log ── */}
      <div className="flex flex-1 flex-col gap-5 min-w-[320px]">
        <PlayerPanel players={players} sessionCount={sessionCount} kills={kills} />
        {Object.keys(channels).length > 0 && <ChannelPanel channels={channels} />}
        <LogPanel logs={logs} logTotal={logTotal} onCopy={copyLogs} onDownload={downloadLogs} />
      </div>
    </div>
  );
}
