import { useEffect, useRef } from "react";
import { portColor } from "../utils/portColor";

// Bounds calibrés session _e (format opAE, marker 22 03 78).
// E/W (Entry.X) : [0, 3324] — N/S (Entry.Y) : [-3480, +3480], Nord = Y max
const BOUNDS = { xMin: 0, xMax: 3324, yMin: -3480, yMax: 3480 };
const CANVAS = 600;
const MAP_BORDER = 12;

export default function Radar({ players }) {
  const canvasRef  = useRef(null);
  const mapImgRef  = useRef(null);
  const playersRef = useRef(players);

  useEffect(() => { playersRef.current = players; }, [players]);

  useEffect(() => {
    const img = new Image();
    img.src = "/map.png";
    img.onload = () => { mapImgRef.current = img; };
  }, []);

  useEffect(() => {
    let animFrame;

    const draw = (t) => {
      const ctx = canvasRef.current?.getContext("2d");
      if (!ctx) return;

      const pulse = (Math.sin(t * 0.002) + 1) / 2; // 0 → 1

      ctx.fillStyle = "#0a0a0a";
      ctx.fillRect(0, 0, CANVAS, CANVAS);

      if (mapImgRef.current) {
        ctx.globalAlpha = 0.55;
        ctx.drawImage(mapImgRef.current, 0, 0, CANVAS, CANVAS);
        ctx.globalAlpha = 1.0;
      }

      ctx.fillStyle = "rgba(0,0,0,0.25)";
      ctx.fillRect(0, 0, CANVAS, CANVAS);

      const drawW = CANVAS - MAP_BORDER * 2;
      const drawH = CANVAS - MAP_BORDER * 2;

      Object.values(playersRef.current).forEach(p => {
        const cx    = MAP_BORDER + (p.x - BOUNDS.xMin) / (BOUNDS.xMax - BOUNDS.xMin) * drawW;
        const cy    = MAP_BORDER + (BOUNDS.yMax - p.y) / (BOUNDS.yMax - BOUNDS.yMin) * drawH;
        const color = portColor(p.port);

        // Outer pulse ring
        ctx.globalAlpha = 0.15 + pulse * 0.45;
        ctx.beginPath();
        ctx.arc(cx, cy, 8 + pulse * 7, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth   = 1.5;
        ctx.stroke();
        ctx.globalAlpha = 1;

        // Inner dot with glow
        ctx.shadowColor = color;
        ctx.shadowBlur  = 6 + pulse * 10;
        ctx.beginPath();
        ctx.arc(cx, cy, 4, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Label
        ctx.shadowColor = "rgba(0,0,0,0.9)";
        ctx.shadowBlur  = 4;
        ctx.fillStyle   = "#ffffff";
        ctx.font        = "bold 10px monospace";
        ctx.fillText(`#${p.transientId} :${p.port}`, cx + 11, cy - 3);
        ctx.fillStyle = "#aaaaaa";
        ctx.font      = "9px monospace";
        ctx.fillText(`${p.x?.toFixed(0)},${p.y?.toFixed(0)}`, cx + 11, cy + 9);
        ctx.shadowBlur = 0;
      });
    };

    const tick = (t) => {
      draw(t);
      animFrame = requestAnimationFrame(tick);
    };
    animFrame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animFrame);
  }, []);

  return (
    <canvas
      ref={canvasRef}
      width={CANVAS}
      height={CANVAS}
      style={{
        border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: 2,
        display: "block",
        width: "100%",
        height: "auto",
      }}
    />
  );
}
