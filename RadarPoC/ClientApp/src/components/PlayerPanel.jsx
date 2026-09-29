import { portColor } from "../utils/portColor";
import KillFeed from "./KillFeed";

export default function PlayerPanel({ players, sessionCount, kills }) {
  const playerList  = Object.values(players);
  const playerCount = playerList.length;

  return (
    <div className="bg-surface border border-white/10 rounded-sm p-6">
      <div className="flex items-end gap-3 mb-1">
        <div className="text-6xl font-bold text-paper leading-none">{playerCount}</div>
        <div className="text-base text-muted mb-1">
          / <span className="text-paper-dim font-medium">{sessionCount}</span> session
        </div>
      </div>
      <div className="text-sm text-muted mb-5">
        joueurs actifs (5 min) · uniques session
      </div>

      <div className="text-sm max-h-36 overflow-y-auto">
        {playerList.map(p => (
          <div
            key={`${p.port}:${p.transientId}`}
            className="flex items-baseline gap-2 py-1.5 border-b border-white/5"
            style={{ color: portColor(p.port) }}
          >
            <span className="text-paper-dim font-medium">{p.name ?? `#${p.transientId}`}</span>
            <span className="text-muted text-xs">{p.x?.toFixed(1)}, {p.y?.toFixed(1)}, {p.z?.toFixed(1)}</span>
            <span className="text-muted ml-auto text-xs">:{p.port}</span>
          </div>
        ))}
        {playerCount === 0 && (
          <div className="text-muted italic py-2 text-sm">en attente de positions...</div>
        )}
      </div>

      <KillFeed kills={kills} />
    </div>
  );
}
