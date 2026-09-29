import { portColor } from "../utils/portColor";

export default function ChannelPanel({ channels }) {
  return (
    <div className="bg-surface border border-white/10 rounded-sm px-5 py-4">
      <div className="text-xs font-semibold uppercase tracking-widest text-muted mb-2">
        Canaux UDP
      </div>
      {Object.values(channels).map(channel => (
        <div key={channel.port} className="flex items-center gap-3 text-xs py-1 border-b border-white/5 last:border-0">
          <span className="font-mono" style={{ color: portColor(channel.port) }}>:{channel.port}</span>
          <span className="text-muted">{channel.protocol}</span>
          <span className="text-muted ml-auto">{channel.serverIp}:{channel.serverPort}</span>
        </div>
      ))}
    </div>
  );
}
