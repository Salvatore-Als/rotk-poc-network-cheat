export default function KillFeed({ kills }) {
  return (
    <div className="mt-5 pt-5 border-t border-white/10">
      <div className="text-sm font-semibold uppercase tracking-widest text-paper-dim mb-3">
        Killfeed
        <span className="text-white/25 font-normal normal-case tracking-normal text-xs ml-2">({kills.length})</span>
      </div>
      <div className="text-sm max-h-40 overflow-y-auto">
        {kills.length === 0 && (
          <div className="text-muted italic">Aucun kill détecté</div>
        )}
        {kills.map((k, i) => (
          <div key={i} className="flex items-center gap-2.5 py-1.5 border-b border-white/5">
            <span className="text-signal text-xs">✕</span>
            <span className="text-paper-dim">{k.killer}</span>
            <span className="text-muted text-xs">→</span>
            <span className="text-paper-dim">{k.victim}</span>
            {k.headshot && (
              <span className="ml-auto text-accent-y text-xs font-semibold tracking-widest">HS</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
