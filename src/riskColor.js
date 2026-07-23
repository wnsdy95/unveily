const RISK_COLOR_STOPS = Object.freeze([
  Object.freeze({ score: 0, rgb: Object.freeze([3, 152, 85]) }),
  Object.freeze({ score: 50, rgb: Object.freeze([220, 104, 3]) }),
  Object.freeze({ score: 100, rgb: Object.freeze([217, 45, 32]) })
]);

export function normalizeRiskScore(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.min(100, Math.max(0, value));
}

function interpolateChannel(start, end, progress) {
  return Math.round(start + (end - start) * progress);
}

function channelHex(channel) {
  return channel.toString(16).padStart(2, "0").toUpperCase();
}

export function riskColorForScore(value) {
  const score = normalizeRiskScore(value);
  if (score === null) return null;

  const upperStopIndex = score <= RISK_COLOR_STOPS[1].score ? 1 : 2;
  const lowerStop = RISK_COLOR_STOPS[upperStopIndex - 1];
  const upperStop = RISK_COLOR_STOPS[upperStopIndex];
  const progress = (score - lowerStop.score) / (upperStop.score - lowerStop.score);
  const rgb = lowerStop.rgb.map((channel, index) =>
    interpolateChannel(channel, upperStop.rgb[index], progress)
  );

  return `#${rgb.map(channelHex).join("")}`;
}
