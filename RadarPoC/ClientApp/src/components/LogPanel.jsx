import { useEffect, useRef } from "react";

const btnClass = "bg-surface-2 border border-white/10 text-muted text-xs px-3 py-1.5 rounded-sm cursor-pointer hover:text-paper-dim hover:border-white/20 transition-colors";

export default function LogPanel({ logs, logTotal, onCopy, onDownload }) {
  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = 0;
  }, [logs]);

  return (
    <div className="bg-surface border border-white/10 rounded-sm p-6 flex flex-1 flex-col min-h-0">
      <div className="flex items-center gap-3 mb-4">
        <span className="text-sm font-semibold uppercase tracking-widest text-paper-dim flex-1">
          Log
          <span className="text-white/25 font-normal normal-case tracking-normal text-xs ml-2">({logTotal})</span>
        </span>
        <button type="button" onClick={onCopy}     className={btnClass}>Copier</button>
        <button type="button" onClick={onDownload} className={btnClass}>.log</button>
      </div>
      <div ref={logRef} className="overflow-y-auto flex-1 font-mono text-xs leading-6">
        {logs.map((line, i) => (
          <div
            key={i}
            className="whitespace-pre-wrap break-all"
            style={{
              color: i === 0                                            ? "#d9d9d9"
                   : line.includes("Clé") || line.includes("✓")       ? "#a7c393"
                   : line.includes("⚠")   || line.includes("sans clé") ? "#d8a244"
                   : "#929292",
            }}
          >
            {line}
          </div>
        ))}
      </div>
    </div>
  );
}
