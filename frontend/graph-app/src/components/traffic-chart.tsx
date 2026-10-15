export function TrafficChart({ period }: { period: string }) {
  const weekly = period === '7 days';
  const values = weekly
    ? [47, 53, 40, 60, 43, 54, 61, 44, 58, 37, 53, 31, 56, 46, 28, 48, 37, 59, 31, 46, 58, 43, 55, 47, 65, 58, 45, 59, 43, 73, 52, 83, 61, 50, 76, 62, 54, 70, 82, 60, 66, 102, 74, 54, 80, 64, 95, 69, 58, 88, 72, 66, 85, 77, 63, 86]
    : [25, 39, 32, 48, 34, 44, 30, 54, 39, 58, 36, 61, 44, 70, 50, 84, 62, 102, 73, 94, 68, 87, 81, 104, 72, 95, 89, 116];
  const points = values.map((v, i) => `${46 + (i * 548) / (values.length - 1)},${160 - v}`).join(' ');
  const baseline = values.map((_, i) => `${46 + (i * 548) / (values.length - 1)},${126 + Math.sin(i * 1.2) * 6}`).join(' ');

  return (
    <svg className="traffic-chart" viewBox="0 0 615 200" role="img" aria-label={`Simulated outbound traffic and peer baseline over ${period}`}>
      {[0, 1, 2, 3].map(i => (
        <g key={i}>
          <line className="chart-grid" x1="46" y1={20 + i * 46} x2="594" y2={20 + i * 46} />
          <text className="chart-label" x="4" y={23 + i * 46}>
            {[1.5, 1, 0.5, 0][i]} GB
          </text>
        </g>
      ))}
      <polygon className="chart-area" points={`46,160 ${points} 594,160`} />
      <polyline className="baseline-line" points={baseline} />
      <polyline className="chart-line" points={points} />
      <circle className="chart-marker" cx="464.5" cy={weekly ? 58 : 79} r="4" />
      {(weekly
        ? ['Oct 09', 'Oct 10', 'Oct 11', 'Oct 12', 'Oct 13', 'Oct 14', 'Oct 15']
        : ['Sep 16', 'Sep 21', 'Sep 26', 'Oct 01', 'Oct 06', 'Oct 11', 'Oct 15']
      ).map((label, i) => (
        <text key={label} className="chart-label" x={46 + i * 91.3} y="184" textAnchor={i === 6 ? 'end' : 'start'}>
          {label}
        </text>
      ))}
    </svg>
  );
}
