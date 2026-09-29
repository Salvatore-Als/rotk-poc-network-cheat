const PORT_COLORS = ["#00ff88", "#ff5c5c", "#55aaff", "#ffcc44", "#cc66ff", "#00dddd"];

export function portColor(port) {
  return PORT_COLORS[Math.abs(port) % PORT_COLORS.length];
}
