const STATUS_STATES = {
  CONNECTING:   { label: "Connexion au serveur...",                            cls: "text-muted    border-white/10" },
  CONNECTED:    { label: "Connecté — en attente du jeu H1Z1",                 cls: "text-accent-g border-accent-g/30" },
  GAME_FOUND:   { label: "Process H1Z1 détecté — capture active",             cls: "text-accent-y border-accent-y/30" },
  DISCONNECTED: { label: "Serveur déconnecté — relancer RadarPoC",            cls: "text-signal   border-signal/30" },
};

export default function StatusBadge({ statusKey }) {
  const { label, cls } = STATUS_STATES[statusKey];
  return (
    <div className={`bg-surface-2 border rounded-sm px-4 py-3 mb-5 text-sm flex items-center gap-3 ${cls}`}>
      <span className="pulse">●</span>
      {label}
    </div>
  );
}
